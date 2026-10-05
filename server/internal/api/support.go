package api

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- JSON helpers ----------

type apiError struct {
	status int
	code   string
	extra  map[string]any
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (e apiError) write(w http.ResponseWriter) {
	m := map[string]any{"error": e.code}
	for k, v := range e.extra {
		m[k] = v
	}
	writeJSON(w, e.status, m)
}

var (
	errBadRequest   = apiError{status: 400, code: "bad_request"}
	errUnauthorized = apiError{status: 401, code: "unauthorized"}
	errForbidden    = apiError{status: 403, code: "forbidden"}
	errNotFound     = apiError{status: 404, code: "not_found"}
	errConflict     = apiError{status: 409, code: "conflict"}
	errTooLarge     = apiError{status: 413, code: "too_large"}
	errQuota        = apiError{status: 429, code: "quota"}
	errRateLimited  = apiError{status: 429, code: "rate_limited"}
	errUnavailable  = apiError{status: 503, code: "unavailable"}
)

// ---------- fixed-window rate limiter (memory only, bounded) ----------

const (
	maxLimiterKeys = 200_000
	maxKeyLen      = 96
)

type window struct {
	start time.Time
	n     int
}

type limiter struct {
	mu sync.Mutex
	m  map[string]*window
}

func newLimiter() *limiter { return &limiter{m: map[string]*window{}} }

// allow counts a hit and reports whether it is within limit/per. A full table
// refuses new keys (fails closed) instead of growing without bound.
func (l *limiter) allow(key string, limit int, per time.Duration, now time.Time) bool {
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.m[key]
	if w == nil || now.Sub(w.start) >= per {
		if w == nil && len(l.m) >= maxLimiterKeys {
			return false
		}
		l.m[key] = &window{start: now, n: 1}
		return true
	}
	if w.n >= limit {
		return false
	}
	w.n++
	return true
}

// count returns the hits recorded in the current window without adding one.
func (l *limiter) count(key string, per time.Duration, now time.Time) int {
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if w := l.m[key]; w != nil && now.Sub(w.start) < per {
		return w.n
	}
	return 0
}

func (l *limiter) sweep(older time.Duration, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.m {
		if now.Sub(w.start) > older {
			delete(l.m, k)
		}
	}
}

// ---------- replay protection (bounded) ----------

const maxNonces = 500_000

type nonceCache struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newNonceCache() *nonceCache { return &nonceCache{m: map[string]time.Time{}} }

// seen records key; dup is true when it was already present inside ttl, full
// when the cache is saturated (the caller must refuse rather than evict, so a
// flood can never make an old nonce replayable).
func (c *nonceCache) seen(key string, now time.Time, ttl time.Duration) (dup, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.m[key]; ok && now.Sub(t) < ttl {
		return true, false
	}
	if len(c.m) >= maxNonces {
		return false, true
	}
	c.m[key] = now
	return false, false
}

func (c *nonceCache) sweep(ttl time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.m {
		if now.Sub(t) >= ttl {
			delete(c.m, k)
		}
	}
}

// ---------- SSE hub ----------

type event struct {
	Collection string `json:"collection"`
	DocID      string `json:"docId"`
	Seq        int64  `json:"seq"`
	Deleted    bool   `json:"deleted"`
}

// subscriber is one open stream. wake only says "something changed": the
// handler re-reads /changes from its own cursor, so a dropped or reordered
// signal can never lose a document.
type subscriber struct {
	gid, pub string
	wake     chan struct{}
	kicked   chan struct{}
	once     sync.Once
}

func (s *subscriber) kick() { s.once.Do(func() { close(s.kicked) }) }

type hub struct {
	mu   sync.Mutex
	subs map[string]map[*subscriber]struct{}
}

func newHub() *hub { return &hub{subs: map[string]map[*subscriber]struct{}{}} }

// subscribe registers a stream, enforcing the per-device and per-group caps.
func (h *hub) subscribe(gid, pub string, maxDevice, maxGroup int) (*subscriber, func(), bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	group := h.subs[gid]
	perDev := 0
	for s := range group {
		if s.pub == pub {
			perDev++
		}
	}
	if len(group) >= maxGroup || perDev >= maxDevice {
		return nil, nil, false
	}
	sub := &subscriber{gid: gid, pub: pub, wake: make(chan struct{}, 1), kicked: make(chan struct{})}
	if group == nil {
		group = map[*subscriber]struct{}{}
		h.subs[gid] = group
	}
	group[sub] = struct{}{}
	return sub, func() {
		h.mu.Lock()
		delete(h.subs[gid], sub)
		if len(h.subs[gid]) == 0 {
			delete(h.subs, gid)
		}
		h.mu.Unlock()
	}, true
}

// notify wakes every stream of the group; never blocks.
func (h *hub) notify(gid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs[gid] {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// kick closes the streams of one device (pub != "" ) or of the whole group.
func (h *hub) kick(gid, pub string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs[gid] {
		if pub == "" || s.pub == pub {
			s.kick()
		}
	}
}

// ---------- metrics (Prometheus text format, no dependency) ----------

type metrics struct {
	req2xx, req4xx, req5xx           atomic.Int64
	rateLimited, authFail, conflicts atomic.Int64
	quotaDenied, votes               atomic.Int64
	purgedGroups, lastPurgeUnix      atomic.Int64
	sseClients, inFlight, shed       atomic.Int64
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(c int) { r.code = c; r.ResponseWriter.WriteHeader(c) }
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// ---------- client address ----------

// clientIP returns the address used for rate limiting: the TCP peer, or — only
// when that peer is a trusted proxy — the validated forwarded address. IPv6 is
// reduced to its /64 so one subscriber cannot mint 2^64 "addresses".
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && s.cfg.TrustProxy && s.trusted(ip) {
		if fwd := net.ParseIP(r.Header.Get(s.cfg.RealIPHeader)); fwd != nil {
			ip = fwd
		}
	}
	if ip == nil {
		return "invalid"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (s *Server) trusted(ip net.IP) bool {
	for _, n := range s.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
