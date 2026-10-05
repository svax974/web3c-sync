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

// ---------- fixed-window rate limiter (memory only) ----------

type window struct {
	start time.Time
	n     int
}

type limiter struct {
	mu sync.Mutex
	m  map[string]*window
}

func newLimiter() *limiter { return &limiter{m: map[string]*window{}} }

func (l *limiter) allow(key string, limit int, per time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.m[key]
	if w == nil || now.Sub(w.start) >= per {
		l.m[key] = &window{start: now, n: 1}
		return true
	}
	if w.n >= limit {
		return false
	}
	w.n++
	return true
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

// ---------- replay protection ----------

type nonceCache struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newNonceCache() *nonceCache { return &nonceCache{m: map[string]time.Time{}} }

// seen records key and reports whether it was already present.
func (c *nonceCache) seen(key string, now time.Time, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.m[key]; ok && now.Sub(t) < ttl {
		return true
	}
	c.m[key] = now
	return false
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

type hub struct {
	mu   sync.Mutex
	subs map[string]map[chan event]struct{}
}

func newHub() *hub { return &hub{subs: map[string]map[chan event]struct{}{}} }

func (h *hub) subscribe(gid string) (chan event, func()) {
	ch := make(chan event, 128)
	h.mu.Lock()
	if h.subs[gid] == nil {
		h.subs[gid] = map[chan event]struct{}{}
	}
	h.subs[gid][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs[gid], ch)
		if len(h.subs[gid]) == 0 {
			delete(h.subs, gid)
		}
		h.mu.Unlock()
	}
}

// publish never blocks; a full subscriber simply misses events and catches up
// through /changes on reconnect.
func (h *hub) publish(gid string, e event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[gid] {
		select {
		case ch <- e:
		default:
		}
	}
}

// ---------- metrics (Prometheus text format, no dependency) ----------

type metrics struct {
	req2xx, req4xx, req5xx           atomic.Int64
	rateLimited, authFail, conflicts atomic.Int64
	quotaDenied, votes               atomic.Int64
	purgedGroups, lastPurgeUnix      atomic.Int64
	sseClients                       atomic.Int64
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

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if v := r.Header.Get(s.cfg.RealIPHeader); v != "" {
			return v
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
