// Package api exposes the web3c-sync v1 HTTP protocol (spec/PROTOCOL.md).
package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"web3c.cc/sync/internal/config"
	"web3c.cc/sync/internal/proto"
	"web3c.cc/sync/internal/store"
)

const (
	clockSkew = 120 * time.Second
	nonceTTL  = 5 * time.Minute
)

var (
	reCollection = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	reBlobID     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reContentKey = regexp.MustCompile(`^[a-z0-9:_.-]{1,128}$`)
)

type Server struct {
	cfg    *config.Config
	st     *store.Store
	hub    *hub
	nonces *nonceCache
	rlIP   *limiter // group creation, per IP
	rlDev  *limiter // writes, per device
	rlVote *limiter // public votes, per IP
	rlRead *limiter // public reads, per IP
	m      metrics
	now    func() time.Time
}

func New(cfg *config.Config, st *store.Store) *Server {
	return &Server{
		cfg: cfg, st: st, hub: newHub(), nonces: newNonceCache(),
		rlIP: newLimiter(), rlDev: newLimiter(), rlVote: newLimiter(), rlRead: newLimiter(),
		now: time.Now,
	}
}

func (s *Server) quota() store.Quota {
	return store.Quota{MaxDocs: s.cfg.MaxDocs, MaxBytes: s.cfg.MaxBytes, MaxBlobSize: s.cfg.MaxBlobSize}
}

// Handler returns the full HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)

	mux.HandleFunc("POST /v1/g", s.signed(modeSigned, 4<<10, s.createGroup))
	mux.HandleFunc("POST /v1/g/{gid}/join-tokens", s.signed(modeOwner, 1<<10, s.createJoinToken))
	mux.HandleFunc("POST /v1/g/{gid}/join", s.signed(modeSigned, 4<<10, s.join))
	mux.HandleFunc("GET /v1/g/{gid}/members", s.signed(modeMember, 0, s.members))
	mux.HandleFunc("DELETE /v1/g/{gid}/members/{device}", s.signed(modeMember, 0, s.removeMember))
	mux.HandleFunc("GET /v1/g/{gid}/info", s.signed(modeMember, 0, s.info))
	mux.HandleFunc("DELETE /v1/g/{gid}", s.signed(modeOwner, 0, s.purge))

	mux.HandleFunc("PUT /v1/g/{gid}/d/{coll}/{doc}", s.signed(modeMember, s.cfg.MaxDocSize+64, s.putDoc))
	mux.HandleFunc("GET /v1/g/{gid}/d/{coll}/{doc}", s.signed(modeMember, 0, s.getDoc))
	mux.HandleFunc("DELETE /v1/g/{gid}/d/{coll}/{doc}", s.signed(modeMember, 0, s.deleteDoc))
	mux.HandleFunc("GET /v1/g/{gid}/changes", s.signed(modeMember, 0, s.changes))
	mux.HandleFunc("GET /v1/g/{gid}/stream", s.signed(modeMember, 0, s.stream))

	mux.HandleFunc("PUT /v1/g/{gid}/b/{blob}", s.signed(modeMember, s.cfg.MaxBlobSize+64, s.putBlob))
	mux.HandleFunc("GET /v1/g/{gid}/b/{blob}", s.signed(modeMember, 0, s.getBlob))
	mux.HandleFunc("DELETE /v1/g/{gid}/b/{blob}", s.signed(modeMember, 0, s.deleteBlob))

	if s.cfg.Community {
		mux.HandleFunc("PUT /v1/public/ratings/{key}", s.putVote)
		mux.HandleFunc("GET /v1/public/ratings/{key}", s.getRating)
		mux.HandleFunc("POST /v1/public/ratings/query", s.queryRatings)
	}
	return s.instrument(mux)
}

func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		switch {
		case rec.code >= 500:
			s.m.req5xx.Add(1)
		case rec.code >= 400:
			s.m.req4xx.Add(1)
		default:
			s.m.req2xx.Add(1)
		}
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "instance": s.cfg.Instance, "v": 1})
}

// ---------- authentication ----------

type mode int

const (
	modeSigned mode = iota // valid signature only (create, join)
	modeMember             // device must be a member of {gid}
	modeOwner              // device must own {gid}
)

type authed struct {
	pub   string
	owner bool
	body  []byte
	gid   string
}

type handler func(w http.ResponseWriter, r *http.Request, a *authed)

func (s *Server) signed(m mode, maxBody int64, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if maxBody > 0 && r.Body != nil {
			lr := http.MaxBytesReader(w, r.Body, maxBody)
			b, err := io.ReadAll(lr)
			if err != nil {
				errTooLarge.write(w)
				return
			}
			body = b
		}
		pub, ok := s.verify(r, body)
		if !ok {
			s.m.authFail.Add(1)
			errUnauthorized.write(w)
			return
		}
		a := &authed{pub: pub, body: body, gid: r.PathValue("gid")}
		if m != modeSigned {
			if !validGroupID(a.gid) {
				errForbidden.write(w)
				return
			}
			member, owner, err := s.st.IsMember(a.gid, pub)
			if err != nil {
				errUnavailable.write(w)
				return
			}
			if !member || (m == modeOwner && !owner) {
				s.m.authFail.Add(1)
				errForbidden.write(w)
				return
			}
			a.owner = owner
		}
		h(w, r, a)
	}
}

// verify checks the request signature (§5) and returns the device key.
func (s *Server) verify(r *http.Request, body []byte) (string, bool) {
	pubB64, ts, nonce, sig := r.Header.Get("X-Device"), r.Header.Get("X-Timestamp"), r.Header.Get("X-Nonce"), r.Header.Get("X-Signature")
	if pubB64 == "" || ts == "" || nonce == "" || sig == "" {
		return "", false
	}
	pub, err := proto.UnB64(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", false
	}
	now := s.now()
	if d := now.Sub(time.Unix(sec, 0)); d > clockSkew || d < -clockSkew {
		return "", false
	}
	if n, err := proto.UnB64(nonce); err != nil || len(n) != 16 {
		return "", false
	}
	canon := proto.Canonical(r.Method, r.RequestURI, ts, nonce, proto.BodyHash(body), s.cfg.Instance)
	if !proto.Verify(pub, canon, sig) {
		return "", false
	}
	// Only record the nonce once the signature is valid, so unauthenticated
	// traffic cannot fill the cache.
	if s.nonces.seen(pubB64+"|"+nonce, now, nonceTTL) {
		return "", false
	}
	return pubB64, true
}

func validGroupID(g string) bool {
	b, err := proto.UnB64(g)
	return err == nil && len(b) == 16 && proto.B64(b) == g
}

func validDocID(d string) bool {
	b, err := proto.UnB64(d)
	return err == nil && len(b) == 32 && proto.B64(b) == d
}

func (s *Server) collectionOK(c string) bool {
	if !reCollection.MatchString(c) {
		return false
	}
	return s.cfg.Collections == nil || s.cfg.Collections[c]
}

// ---------- groups ----------

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, a *authed) {
	if s.cfg.AdminTokenHash != "" {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(tok))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(s.cfg.AdminTokenHash)) != 1 {
			s.m.authFail.Add(1)
			errForbidden.write(w)
			return
		}
	}
	if !s.rlIP.allow("create|"+s.clientIP(r), s.cfg.CreatesPerDay, 24*time.Hour, s.now()) {
		s.m.rateLimited.Add(1)
		errRateLimited.write(w)
		return
	}
	var req struct {
		GroupID string `json:"groupId"`
		NameEnc string `json:"nameEnc"`
	}
	if json.Unmarshal(a.body, &req) != nil || !validGroupID(req.GroupID) || len(req.NameEnc) > 512 {
		errBadRequest.write(w)
		return
	}
	switch err := s.st.CreateGroup(req.GroupID, a.pub, req.NameEnc); {
	case errors.Is(err, store.ErrExists):
		errConflict.write(w)
	case err != nil:
		errUnavailable.write(w)
	default:
		writeJSON(w, 201, map[string]any{"groupId": req.GroupID})
	}
}

func (s *Server) createJoinToken(w http.ResponseWriter, _ *http.Request, a *authed) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		errUnavailable.write(w)
		return
	}
	tok := proto.B64(raw)
	exp := s.now().Add(s.cfg.JoinTokenTTL)
	if err := s.st.AddJoinToken(a.gid, hashToken(tok), exp); err != nil {
		errUnavailable.write(w)
		return
	}
	writeJSON(w, 201, map[string]any{"token": tok, "expiresAt": exp.Unix()})
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *Server) join(w http.ResponseWriter, _ *http.Request, a *authed) {
	var req struct {
		Token   string `json:"token"`
		NameEnc string `json:"nameEnc"`
	}
	if json.Unmarshal(a.body, &req) != nil || !validGroupID(a.gid) || req.Token == "" || len(req.NameEnc) > 512 {
		errForbidden.write(w) // identical to a bad token: no oracle
		return
	}
	ok, err := s.st.Join(a.gid, hashToken(req.Token), a.pub, req.NameEnc)
	if err != nil {
		errUnavailable.write(w)
		return
	}
	if !ok {
		s.m.authFail.Add(1)
		errForbidden.write(w)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) members(w http.ResponseWriter, _ *http.Request, a *authed) {
	ms, err := s.st.Members(a.gid)
	if err != nil {
		errUnavailable.write(w)
		return
	}
	writeJSON(w, 200, ms)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, a *authed) {
	dev := r.PathValue("device")
	if !a.owner && dev != a.pub {
		errForbidden.write(w)
		return
	}
	switch err := s.st.RemoveMember(a.gid, dev); {
	case errors.Is(err, store.ErrNotFound):
		errNotFound.write(w)
	case err != nil:
		errUnavailable.write(w)
	default:
		w.WriteHeader(204)
	}
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request, a *authed) {
	i, err := s.st.Info(a.gid)
	if err != nil {
		errNotFound.write(w)
		return
	}
	purge := time.Unix(i.LastActivity, 0).Add(time.Duration(s.cfg.RetentionDays) * 24 * time.Hour).Unix()
	writeJSON(w, 200, map[string]any{
		"instance": s.cfg.Instance, "seq": i.Seq, "docs": i.Docs, "bytes": i.Bytes,
		"members": i.Members, "purgeAt": purge,
		"quota": map[string]any{"maxDocs": s.cfg.MaxDocs, "maxBytes": s.cfg.MaxBytes, "maxDocSize": s.cfg.MaxDocSize},
	})
}

func (s *Server) purge(w http.ResponseWriter, _ *http.Request, a *authed) {
	if err := s.st.PurgeGroup(a.gid); err != nil {
		errUnavailable.write(w)
		return
	}
	w.WriteHeader(204)
}

// ---------- documents ----------

func ifMatch(r *http.Request) (int64, bool) {
	v := strings.Trim(r.Header.Get("If-Match"), `"`)
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}

func (s *Server) docRoute(r *http.Request) (coll, doc string, ok bool) {
	coll, doc = r.PathValue("coll"), r.PathValue("doc")
	return coll, doc, s.collectionOK(coll) && validDocID(doc)
}

func (s *Server) deviceLimit(w http.ResponseWriter, a *authed) bool {
	if !s.rlDev.allow("w|"+a.pub, s.cfg.WritesPerMin, time.Minute, s.now()) {
		s.m.rateLimited.Add(1)
		errRateLimited.write(w)
		return false
	}
	return true
}

func (s *Server) putDoc(w http.ResponseWriter, r *http.Request, a *authed) {
	coll, doc, ok := s.docRoute(r)
	im, ok2 := ifMatch(r)
	if !ok || !ok2 || len(a.body) == 0 {
		errBadRequest.write(w)
		return
	}
	if int64(len(a.body)) > s.cfg.MaxDocSize {
		errTooLarge.write(w)
		return
	}
	if !s.deviceLimit(w, a) {
		return
	}
	seq, cur, err := s.st.PutDoc(a.gid, coll, doc, a.body, im, s.quota())
	s.finishWrite(w, a.gid, coll, doc, seq, cur, false, err)
}

func (s *Server) deleteDoc(w http.ResponseWriter, r *http.Request, a *authed) {
	coll, doc, ok := s.docRoute(r)
	im, ok2 := ifMatch(r)
	if !ok || !ok2 {
		errBadRequest.write(w)
		return
	}
	if !s.deviceLimit(w, a) {
		return
	}
	seq, cur, err := s.st.DeleteDoc(a.gid, coll, doc, im)
	s.finishWrite(w, a.gid, coll, doc, seq, cur, true, err)
}

func (s *Server) finishWrite(w http.ResponseWriter, gid, coll, doc string, seq, cur int64, deleted bool, err error) {
	switch {
	case errors.Is(err, store.ErrConflict):
		s.m.conflicts.Add(1)
		e := errConflict
		e.extra = map[string]any{"seq": cur}
		e.write(w)
	case errors.Is(err, store.ErrQuota):
		s.m.quotaDenied.Add(1)
		e := errQuota
		e.extra = map[string]any{"limit": "group"}
		e.write(w)
	case errors.Is(err, store.ErrNotFound):
		errNotFound.write(w)
	case err != nil:
		errUnavailable.write(w)
	default:
		s.hub.publish(gid, event{Collection: coll, DocID: doc, Seq: seq, Deleted: deleted})
		writeJSON(w, 200, map[string]any{"seq": seq})
	}
}

func (s *Server) getDoc(w http.ResponseWriter, r *http.Request, a *authed) {
	coll, doc, ok := s.docRoute(r)
	if !ok {
		errBadRequest.write(w)
		return
	}
	d, err := s.st.GetDoc(a.gid, coll, doc)
	if err != nil {
		errNotFound.write(w)
		return
	}
	w.Header().Set("X-Seq", strconv.FormatInt(d.Seq, 10))
	w.Header().Set("X-Updated-At", strconv.FormatInt(d.UpdatedAt, 10))
	if d.Deleted {
		w.Header().Set("X-Deleted", "1")
		w.WriteHeader(410)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(d.Env)
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request, a *authed) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit := 500
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v < 500 {
		limit = v
	}
	items, more, err := s.st.Changes(a.gid, since, limit)
	if err != nil {
		errUnavailable.write(w)
		return
	}
	type item struct {
		Collection string `json:"collection"`
		DocID      string `json:"docId"`
		Seq        int64  `json:"seq"`
		Deleted    bool   `json:"deleted"`
		UpdatedAt  int64  `json:"updatedAt"`
		Env        string `json:"env,omitempty"`
	}
	out := make([]item, 0, len(items))
	next := since
	for _, d := range items {
		it := item{Collection: d.Collection, DocID: d.DocID, Seq: d.Seq, Deleted: d.Deleted, UpdatedAt: d.UpdatedAt}
		if !d.Deleted {
			it.Env = proto.B64(d.Env)
		}
		out = append(out, it)
		next = d.Seq
	}
	writeJSON(w, 200, map[string]any{"items": out, "next": next, "more": more})
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, a *authed) {
	fl, ok := w.(http.Flusher)
	if !ok {
		errUnavailable.write(w)
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	s.m.sseClients.Add(1)
	defer s.m.sseClients.Add(-1)

	ch, unsub := s.hub.subscribe(a.gid)
	defer unsub()
	last := since
	send := func(e event) bool {
		if e.Seq <= last {
			return true
		}
		b, _ := json.Marshal(e)
		if _, err := fmt.Fprintf(w, "id: %d\nevent: change\ndata: %s\n\n", e.Seq, b); err != nil {
			return false
		}
		last = e.Seq
		fl.Flush()
		return true
	}
	// Replay anything missed since the cursor, then follow live.
	for {
		items, more, err := s.st.Changes(a.gid, last, 500)
		if err != nil {
			return
		}
		for _, d := range items {
			if !send(event{Collection: d.Collection, DocID: d.DocID, Seq: d.Seq, Deleted: d.Deleted}) {
				return
			}
		}
		if !more {
			break
		}
	}
	fl.Flush()
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if !send(e) {
				return
			}
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// ---------- blobs ----------

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request, a *authed) {
	id := r.PathValue("blob")
	if !reBlobID.MatchString(id) || len(a.body) == 0 {
		errBadRequest.write(w)
		return
	}
	if !s.deviceLimit(w, a) {
		return
	}
	switch err := s.st.PutBlob(a.gid, id, a.body, s.quota()); {
	case errors.Is(err, store.ErrQuota):
		s.m.quotaDenied.Add(1)
		errQuota.write(w)
	case err != nil:
		errUnavailable.write(w)
	default:
		w.WriteHeader(204)
	}
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request, a *authed) {
	id := r.PathValue("blob")
	if !reBlobID.MatchString(id) {
		errBadRequest.write(w)
		return
	}
	f, st, err := s.st.OpenBlob(a.gid, id)
	if err != nil {
		errNotFound.write(w)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", st.ModTime(), f) // handles Range
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request, a *authed) {
	id := r.PathValue("blob")
	if !reBlobID.MatchString(id) {
		errBadRequest.write(w)
		return
	}
	switch err := s.st.DeleteBlob(a.gid, id); {
	case errors.Is(err, store.ErrNotFound):
		errNotFound.write(w)
	case err != nil:
		errUnavailable.write(w)
	default:
		w.WriteHeader(204)
	}
}

// ---------- public community ratings (§9) ----------

func (s *Server) putVote(w http.ResponseWriter, r *http.Request) {
	if !s.rlVote.allow("v|"+s.clientIP(r), s.cfg.VotesPerMin, time.Minute, s.now()) {
		s.m.rateLimited.Add(1)
		errRateLimited.write(w)
		return
	}
	key := r.PathValue("key")
	if !reContentKey.MatchString(key) {
		errBadRequest.write(w)
		return
	}
	var req struct {
		P string   `json:"p"`
		R *float64 `json:"r"`
		N uint64   `json:"n"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	if err := dec.Decode(&req); err != nil {
		errBadRequest.write(w)
		return
	}
	if p, err := proto.UnB64(req.P); err != nil || len(p) != 32 || proto.B64(p) != req.P {
		errBadRequest.write(w)
		return
	}
	if req.R != nil && !proto.ValidRating(*req.R, s.cfg.RatingMin, s.cfg.RatingMax) {
		errBadRequest.write(w)
		return
	}
	if !proto.PowOK(key, req.P, req.R, req.N, s.cfg.PowBits) {
		errForbidden.write(w)
		return
	}
	if err := s.st.PutRating(key, req.P, req.R); err != nil {
		errUnavailable.write(w)
		return
	}
	s.m.votes.Add(1)
	w.WriteHeader(204)
}

func (s *Server) readLimit(w http.ResponseWriter, r *http.Request) bool {
	if !s.rlRead.allow("r|"+s.clientIP(r), 240, time.Minute, s.now()) {
		s.m.rateLimited.Add(1)
		errRateLimited.write(w)
		return false
	}
	return true
}

func (s *Server) getRating(w http.ResponseWriter, r *http.Request) {
	if !s.readLimit(w, r) {
		return
	}
	key := r.PathValue("key")
	if !reContentKey.MatchString(key) {
		errBadRequest.write(w)
		return
	}
	m, err := s.st.Aggregates([]string{key})
	if err != nil {
		errUnavailable.write(w)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, 200, m[key])
}

func (s *Server) queryRatings(w http.ResponseWriter, r *http.Request) {
	if !s.readLimit(w, r) {
		return
	}
	var req struct {
		Keys []string `json:"keys"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req) != nil || len(req.Keys) == 0 || len(req.Keys) > 100 {
		errBadRequest.write(w)
		return
	}
	for _, k := range req.Keys {
		if !reContentKey.MatchString(k) {
			errBadRequest.write(w)
			return
		}
	}
	m, err := s.st.Aggregates(req.Keys)
	if err != nil {
		errUnavailable.write(w)
		return
	}
	writeJSON(w, 200, map[string]any{"items": m})
}

// ---------- maintenance & metrics ----------

// Maintain runs periodic housekeeping until stop is closed.
func (s *Server) Maintain(stop <-chan struct{}) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			now := s.now()
			s.nonces.sweep(nonceTTL, now)
			s.rlDev.sweep(time.Hour, now)
			s.rlVote.sweep(time.Hour, now)
			s.rlRead.sweep(time.Hour, now)
			s.rlIP.sweep(48*time.Hour, now)
			ids, _ := s.st.PurgeInactive(now.Add(-time.Duration(s.cfg.RetentionDays) * 24 * time.Hour))
			s.m.purgedGroups.Add(int64(len(ids)))
			s.m.lastPurgeUnix.Store(now.Unix())
		}
	}
}

// MetricsHandler serves Prometheus text format; bind it to a private address.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		groups, docs, bytes, ratings, err := s.st.Totals()
		up := 1
		if err != nil {
			up = 0
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		in := s.cfg.Instance
		p := func(name, typ, help string, v any) {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s{instance=%q} %v\n", name, help, name, typ, name, in, v)
		}
		p("sync_up", "gauge", "1 if the service and its database are healthy", up)
		p("sync_groups", "gauge", "Number of sync groups", groups)
		p("sync_docs", "gauge", "Number of live documents", docs)
		p("sync_bytes", "gauge", "Stored ciphertext bytes", bytes)
		p("sync_community_ratings", "gauge", "Public rating votes stored", ratings)
		p("sync_sse_clients", "gauge", "Connected SSE clients", s.m.sseClients.Load())
		p("sync_requests_2xx_total", "counter", "Responses 2xx/3xx", s.m.req2xx.Load())
		p("sync_requests_4xx_total", "counter", "Responses 4xx", s.m.req4xx.Load())
		p("sync_requests_5xx_total", "counter", "Responses 5xx", s.m.req5xx.Load())
		p("sync_rate_limited_total", "counter", "Rate-limited requests", s.m.rateLimited.Load())
		p("sync_auth_failures_total", "counter", "Authentication or membership failures", s.m.authFail.Load())
		p("sync_conflicts_total", "counter", "If-Match conflicts", s.m.conflicts.Load())
		p("sync_quota_denied_total", "counter", "Writes refused by quota", s.m.quotaDenied.Load())
		p("sync_votes_total", "counter", "Accepted community votes", s.m.votes.Load())
		p("sync_purged_groups_total", "counter", "Groups purged for inactivity", s.m.purgedGroups.Load())
		p("sync_last_purge_timestamp_seconds", "gauge", "Last housekeeping run", s.m.lastPurgeUnix.Load())
	})
}
