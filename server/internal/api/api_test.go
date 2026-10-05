package api

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"web3c.cc/sync/internal/config"
	"web3c.cc/sync/internal/proto"
	"web3c.cc/sync/internal/store"
)

const instance = "iptv"

type env struct {
	t   *testing.T
	ts  *httptest.Server
	srv *Server
	cfg *config.Config
	st  *store.Store
}

func newEnv(t *testing.T, mut func(*config.Config)) *env {
	t.Helper()
	cfg := &config.Config{
		Instance: instance, Community: true, PowBits: 8, RatingMin: 0, RatingMax: 10,
		MaxDocSize: 1 << 10, MaxDocs: 5, MaxBytes: 64 << 10, MaxBlobSize: 4 << 10,
		WritesPerMin: 1000, CreatesPerDay: 100, VotesPerMin: 1000, RetentionDays: 365,
		JoinTokenTTL: 10 * time.Minute,
		Collections:  map[string]bool{"progress": true, "ratings": true},

		ReqsPerMin: 100000, MaxStreamsDevice: 3, MaxStreamsGroup: 20, MaxStreamDuration: time.Hour,
		MaxMembers: 50, MaxActiveTokens: 5, MaxRowsFactor: 2, MaxBlobs: 200, BlobMinCost: 512,
		TombstoneDays: 180, ChangesMaxBytes: 4 << 20, MaxInFlight: 256, VotesPerDay: 100000,
		MaxRatings: 1000, AdminFailsPerHour: 10,
	}
	if mut != nil {
		mut(cfg)
	}
	st, err := store.Open(":memory:", filepath.Join(t.TempDir(), "b"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); st.Close() })
	return &env{t, ts, srv, cfg, st}
}

type dev struct {
	e    *env
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	b64  string
}

func (e *env) newDev() *dev {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &dev{e, pub, priv, proto.B64(pub)}
}

func (d *dev) do(method, path string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	return d.doAt(method, path, body, hdr, time.Now(), nil)
}

func (d *dev) doAt(method, path string, body []byte, hdr map[string]string, at time.Time, nonce []byte) (*http.Response, []byte) {
	d.e.t.Helper()
	if nonce == nil {
		nonce = make([]byte, 16)
		rand.Read(nonce)
	}
	ts, nn := strconv.FormatInt(at.Unix(), 10), proto.B64(nonce)
	canon := proto.Canonical(method, path, ts, nn, proto.BodyHash(body), instance)
	req, _ := http.NewRequest(method, d.e.ts.URL+path, bytes.NewReader(body))
	req.Header.Set("X-Device", d.b64)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nn)
	req.Header.Set("X-Signature", proto.Sign(d.priv, canon))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		d.e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func (d *dev) expect(status int, method, path string, body []byte, hdr map[string]string) []byte {
	d.e.t.Helper()
	res, b := d.do(method, path, body, hdr)
	if res.StatusCode != status {
		d.e.t.Fatalf("%s %s: got %d want %d: %s", method, path, res.StatusCode, status, b)
	}
	return b
}

func gid(i byte) string   { return proto.B64(bytes.Repeat([]byte{i}, 16)) }
func docid(i byte) string { return proto.B64(bytes.Repeat([]byte{i}, 32)) }

func (d *dev) createGroup(g string) {
	d.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+g+`"}`), nil)
}

func (d *dev) joinWith(owner *dev, g string) {
	b := owner.expect(201, "POST", "/v1/g/"+g+"/join-tokens", nil, nil)
	var tok struct{ Token string }
	json.Unmarshal(b, &tok)
	d.expect(200, "POST", "/v1/g/"+g+"/join", []byte(`{"token":"`+tok.Token+`","nameEnc":"x"}`), nil)
}

func TestUnsignedAndBadSignatureRejected(t *testing.T) {
	e := newEnv(t, nil)
	res, _ := http.Post(e.ts.URL+"/v1/g", "application/json", strings.NewReader(`{}`))
	if res.StatusCode != 401 {
		t.Fatalf("unsigned: %d", res.StatusCode)
	}
	d := e.newDev()
	// Tampered body after signing.
	canon := proto.Canonical("POST", "/v1/g", strconv.FormatInt(time.Now().Unix(), 10), "AAAAAAAAAAAAAAAAAAAAAA", proto.BodyHash([]byte("a")), instance)
	req, _ := http.NewRequest("POST", e.ts.URL+"/v1/g", strings.NewReader("b"))
	req.Header.Set("X-Device", d.b64)
	req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Nonce", "AAAAAAAAAAAAAAAAAAAAAA")
	req.Header.Set("X-Signature", proto.Sign(d.priv, canon))
	res, _ = http.DefaultClient.Do(req)
	if res.StatusCode != 401 {
		t.Fatalf("tampered body: %d", res.StatusCode)
	}
}

func TestReplayAndClockSkew(t *testing.T) {
	e := newEnv(t, nil)
	d := e.newDev()
	nonce := bytes.Repeat([]byte{9}, 16)
	g := gid(1)
	res, _ := d.doAt("POST", "/v1/g", []byte(`{"groupId":"`+g+`"}`), nil, time.Now(), nonce)
	if res.StatusCode != 201 {
		t.Fatal(res.StatusCode)
	}
	res, _ = d.doAt("POST", "/v1/g", []byte(`{"groupId":"`+g+`"}`), nil, time.Now(), nonce)
	if res.StatusCode != 401 {
		t.Fatalf("replay accepted: %d", res.StatusCode)
	}
	res, _ = d.doAt("GET", "/v1/g/"+g+"/info", nil, nil, time.Now().Add(-10*time.Minute), nil)
	if res.StatusCode != 401 {
		t.Fatalf("stale timestamp accepted: %d", res.StatusCode)
	}
}

func TestMembershipAndPairing(t *testing.T) {
	e := newEnv(t, nil)
	owner, other, stranger := e.newDev(), e.newDev(), e.newDev()
	g := gid(2)
	owner.createGroup(g)
	owner.expect(409, "POST", "/v1/g", []byte(`{"groupId":"`+g+`"}`), nil) // already exists
	stranger.expect(403, "GET", "/v1/g/"+g+"/info", nil, nil)

	// Bad / reused tokens are indistinguishable.
	other.expect(403, "POST", "/v1/g/"+g+"/join", []byte(`{"token":"nope","nameEnc":"x"}`), nil)
	b := owner.expect(201, "POST", "/v1/g/"+g+"/join-tokens", nil, nil)
	var tok struct{ Token string }
	json.Unmarshal(b, &tok)
	body := []byte(`{"token":"` + tok.Token + `","nameEnc":"x"}`)
	other.expect(200, "POST", "/v1/g/"+g+"/join", body, nil)
	stranger.expect(403, "POST", "/v1/g/"+g+"/join", body, nil) // single use
	other.expect(200, "GET", "/v1/g/"+g+"/info", nil, nil)
	// A non-owner cannot mint tokens, revoke others, or purge.
	other.expect(403, "POST", "/v1/g/"+g+"/join-tokens", nil, nil)
	other.expect(403, "DELETE", "/v1/g/"+g+"/members/"+owner.b64, nil, nil)
	other.expect(403, "DELETE", "/v1/g/"+g, nil, nil)
	// Owner revokes; the device loses access immediately. Owner cannot be removed.
	owner.expect(204, "DELETE", "/v1/g/"+g+"/members/"+other.b64, nil, nil)
	other.expect(403, "GET", "/v1/g/"+g+"/info", nil, nil)
	owner.expect(404, "DELETE", "/v1/g/"+g+"/members/"+owner.b64, nil, nil)
}

func TestJoinTokenExpiry(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.JoinTokenTTL = -time.Minute }) // already expired
	owner, other := e.newDev(), e.newDev()
	g := gid(3)
	owner.createGroup(g)
	b := owner.expect(201, "POST", "/v1/g/"+g+"/join-tokens", nil, nil)
	var tok struct{ Token string }
	json.Unmarshal(b, &tok)
	other.expect(403, "POST", "/v1/g/"+g+"/join", []byte(`{"token":"`+tok.Token+`","nameEnc":"x"}`), nil)
}

func TestDocumentsOptimisticConcurrencyAndTombstones(t *testing.T) {
	e := newEnv(t, nil)
	a, b := e.newDev(), e.newDev()
	g := gid(4)
	a.createGroup(g)
	b.joinWith(a, g)
	p := "/v1/g/" + g + "/d/progress/" + docid(1)

	a.expect(400, "PUT", p, []byte("v1"), nil) // If-Match required
	a.expect(200, "PUT", p, []byte("v1"), map[string]string{"If-Match": "0"})
	res, body := b.do("PUT", p, []byte("other"), map[string]string{"If-Match": "0"}) // create when exists
	if res.StatusCode != 409 || !strings.Contains(string(body), `"seq":1`) {
		t.Fatalf("expected 409 with seq: %d %s", res.StatusCode, body)
	}
	b.expect(200, "PUT", p, []byte("v2"), map[string]string{"If-Match": "1"})
	a.expect(409, "PUT", p, []byte("stale"), map[string]string{"If-Match": "1"})
	if got := a.expect(200, "GET", p, nil, nil); string(got) != "v2" {
		t.Fatalf("got %q", got)
	}
	// Tombstone: GET → 410, changes carries deleted, re-create needs the tombstone seq.
	a.expect(200, "DELETE", p, nil, map[string]string{"If-Match": "2"})
	a.expect(410, "GET", p, nil, nil)
	var ch struct {
		Items []struct {
			Deleted bool
			Seq     int64
			Env     string
		}
		Next int64
	}
	json.Unmarshal(a.expect(200, "GET", "/v1/g/"+g+"/changes?since=0", nil, nil), &ch)
	if len(ch.Items) != 1 || !ch.Items[0].Deleted || ch.Items[0].Env != "" || ch.Next != 3 {
		t.Fatalf("changes: %+v", ch)
	}
	a.expect(200, "PUT", p, []byte("again"), map[string]string{"If-Match": "3"})
}

func TestValidationAndQuotas(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newDev()
	g := gid(5)
	a.createGroup(g)
	if res, _ := a.do("PUT", "/v1/g/"+g+"/d/forbidden/"+docid(1), []byte("x"), map[string]string{"If-Match": "0"}); res.StatusCode != 400 {
		t.Fatalf("collection not allowed: %d", res.StatusCode)
	}
	if res, _ := a.do("PUT", "/v1/g/"+g+"/d/progress/short", []byte("x"), map[string]string{"If-Match": "0"}); res.StatusCode != 400 {
		t.Fatalf("bad doc id: %d", res.StatusCode)
	}
	if res, _ := a.do("PUT", "/v1/g/"+g+"/d/progress/"+docid(1), bytes.Repeat([]byte{1}, 2<<10), map[string]string{"If-Match": "0"}); res.StatusCode != 413 {
		t.Fatalf("oversize doc: %d", res.StatusCode)
	}
	for i := byte(1); i <= 5; i++ { // MaxDocs = 5
		a.expect(200, "PUT", "/v1/g/"+g+"/d/progress/"+docid(i), []byte("x"), map[string]string{"If-Match": "0"})
	}
	if res, _ := a.do("PUT", "/v1/g/"+g+"/d/progress/"+docid(9), []byte("x"), map[string]string{"If-Match": "0"}); res.StatusCode != 429 {
		t.Fatalf("doc quota: %d", res.StatusCode)
	}
	// Deleting frees quota.
	a.expect(200, "DELETE", "/v1/g/"+g+"/d/progress/"+docid(1), nil, map[string]string{"If-Match": "1"})
	a.expect(200, "PUT", "/v1/g/"+g+"/d/progress/"+docid(9), []byte("x"), map[string]string{"If-Match": "0"})
}

func TestAdminTokenRequiredWhenConfigured(t *testing.T) {
	sum := "" // sha256("secret")
	{
		var b [32]byte = sha256Sum("secret")
		sum = hexOf(b[:])
	}
	e := newEnv(t, func(c *config.Config) { c.AdminTokenHash = sum })
	d := e.newDev()
	d.expect(403, "POST", "/v1/g", []byte(`{"groupId":"`+gid(6)+`"}`), nil)
	d.expect(403, "POST", "/v1/g", []byte(`{"groupId":"`+gid(6)+`"}`), map[string]string{"Authorization": "Bearer wrong"})
	d.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+gid(6)+`"}`), map[string]string{"Authorization": "Bearer secret"})
}

func TestCreationRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.CreatesPerDay = 2 })
	d := e.newDev()
	d.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+gid(10)+`"}`), nil)
	d.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+gid(11)+`"}`), nil)
	d.expect(429, "POST", "/v1/g", []byte(`{"groupId":"`+gid(12)+`"}`), nil)
}

func TestBlobsWithRangeAndPurge(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newDev()
	g := gid(7)
	a.createGroup(g)
	a.expect(204, "PUT", "/v1/g/"+g+"/b/abc", []byte("0123456789"), nil)
	res, body := a.do("GET", "/v1/g/"+g+"/b/abc", nil, map[string]string{"Range": "bytes=2-5"})
	if res.StatusCode != 206 || string(body) != "2345" {
		t.Fatalf("range: %d %q", res.StatusCode, body)
	}
	if res, _ := a.do("PUT", "/v1/g/"+g+"/b/big", bytes.Repeat([]byte{1}, 8<<10), nil); res.StatusCode != 413 && res.StatusCode != 429 {
		t.Fatalf("blob size cap: %d", res.StatusCode)
	}
	a.expect(204, "DELETE", "/v1/g/"+g+"/b/abc", nil, nil)
	a.expect(404, "GET", "/v1/g/"+g+"/b/abc", nil, nil)
	a.expect(204, "DELETE", "/v1/g/"+g, nil, nil)
	a.expect(403, "GET", "/v1/g/"+g+"/info", nil, nil)
}

func TestSSEStreamReplayAndLive(t *testing.T) {
	e := newEnv(t, nil)
	a := e.newDev()
	g := gid(8)
	a.createGroup(g)
	a.expect(200, "PUT", "/v1/g/"+g+"/d/progress/"+docid(1), []byte("x"), map[string]string{"If-Match": "0"})

	path := "/v1/g/" + g + "/stream?since=0"
	nonce := make([]byte, 16)
	rand.Read(nonce)
	ts, nn := strconv.FormatInt(time.Now().Unix(), 10), proto.B64(nonce)
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	req.Header.Set("X-Device", a.b64)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nn)
	req.Header.Set("X-Signature", proto.Sign(a.priv, proto.Canonical("GET", path, ts, nn, proto.BodyHash(nil), instance)))
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("stream: %v %v", err, res)
	}
	defer res.Body.Close()
	rd := bufio.NewReader(res.Body)
	readEvent := func() string {
		var data string
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(line, "data: ") {
				data = strings.TrimSpace(strings.TrimPrefix(line, "data: "))
			}
			if line == "\n" && data != "" {
				return data
			}
		}
	}
	if d := readEvent(); !strings.Contains(d, `"seq":1`) {
		t.Fatalf("replay: %s", d)
	}
	go a.do("PUT", "/v1/g/"+g+"/d/progress/"+docid(2), []byte("y"), map[string]string{"If-Match": "0"})
	if d := readEvent(); !strings.Contains(d, `"seq":2`) {
		t.Fatalf("live: %s", d)
	}
}

func TestCommunityRatings(t *testing.T) {
	e := newEnv(t, nil)
	put := func(key, pseud string, r *float64, ts int64, n uint64) int {
		b, _ := json.Marshal(map[string]any{"p": pseud, "r": r, "t": ts, "n": n})
		req, _ := http.NewRequest("PUT", e.ts.URL+"/v1/public/ratings/"+key, bytes.NewReader(b))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	key := "movie:tmdb:603"
	now := time.Now().Unix()
	p1, p2 := proto.B64(bytes.Repeat([]byte{1}, 32)), proto.B64(bytes.Repeat([]byte{2}, 32))
	r8, r4, r11 := 8.0, 4.0, 11.0
	bad := uint64(0)
	for proto.PowOK(key, p1, &r8, now, bad, 8) {
		bad++
	}
	if c := put(key, p1, &r8, now, bad); c != 403 {
		t.Fatalf("missing PoW must be refused: %d", c)
	}
	if c := put(key, p1, &r8, now, proto.SolvePow(key, p1, &r8, now, 8)); c != 204 {
		t.Fatalf("vote: %d", c)
	}
	if c := put(key, p2, &r4, now, proto.SolvePow(key, p2, &r4, now, 8)); c != 204 {
		t.Fatalf("vote 2: %d", c)
	}
	if c := put(key, p2, &r11, now+1, proto.SolvePow(key, p2, &r11, now+1, 8)); c != 400 {
		t.Fatalf("out of range: %d", c)
	}
	// Timestamp outside the window is refused (no re-dating / stockpiling).
	if c := put(key, p1, &r4, now-3600, proto.SolvePow(key, p1, &r4, now-3600, 8)); c != 400 {
		t.Fatalf("stale timestamp accepted: %d", c)
	}
	res, _ := http.Get(e.ts.URL + "/v1/public/ratings/" + key)
	var agg struct {
		Count int
		Sum   float64
		Avg   float64
	}
	json.NewDecoder(res.Body).Decode(&agg)
	res.Body.Close()
	if agg.Count != 2 || agg.Sum != 12 || agg.Avg != 6 {
		t.Fatalf("aggregate: %+v", agg)
	}
	// A newer vote replaces; replaying an OLDER captured vote never does.
	if c := put(key, p1, &r4, now+5, proto.SolvePow(key, p1, &r4, now+5, 8)); c != 204 {
		t.Fatalf("revote: %d", c)
	}
	if c := put(key, p1, &r8, now, proto.SolvePow(key, p1, &r8, now, 8)); c != 409 {
		t.Fatalf("replay of an older vote must be refused: %d", c)
	}
	if c := put(key, p1, &r4, now+5, proto.SolvePow(key, p1, &r4, now+5, 8)); c != 409 {
		t.Fatalf("replay of the same vote must be refused: %d", c)
	}
	// Removal is a vote too (null), ordered by the same timestamp.
	if c := put(key, p2, nil, now+6, proto.SolvePow(key, p2, nil, now+6, 8)); c != 204 {
		t.Fatalf("remove: %d", c)
	}
	// Content keys are restricted to TMDB ids: no unbounded key space.
	if c := put("anything:goes", p1, &r4, now, 0); c != 400 {
		t.Fatalf("free-form content key accepted: %d", c)
	}
	b, _ := json.Marshal(map[string]any{"keys": []string{key, "movie:tmdb:1"}})
	res, _ = http.Post(e.ts.URL+"/v1/public/ratings/query", "application/json", bytes.NewReader(b))
	var q struct {
		Items map[string]struct {
			Count int
			Sum   float64
		}
	}
	json.NewDecoder(res.Body).Decode(&q)
	res.Body.Close()
	if q.Items[key].Count != 1 || q.Items[key].Sum != 4 || q.Items["movie:tmdb:1"].Count != 0 {
		t.Fatalf("query: %+v", q)
	}
}

func TestCommunityDisabledOutsideIPTV(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Community = false })
	res, _ := http.Get(e.ts.URL + "/v1/public/ratings/x")
	if res.StatusCode != 404 {
		t.Fatalf("got %d", res.StatusCode)
	}
}

func TestServerNeverStoresPlaintextOrIPs(t *testing.T) {
	// The store only ever receives the opaque envelope; sanity-check that an
	// encrypted payload round-trips byte-for-byte and the metrics endpoint
	// reports the group.
	e := newEnv(t, nil)
	a := e.newDev()
	g := gid(13)
	a.createGroup(g)
	keys := proto.DeriveKeys(bytes.Repeat([]byte{5}, 32))
	doc := proto.DocID(keys.ID, "progress", "movie_1")
	envb, _ := proto.Seal(keys.Enc, proto.AAD(instance, g, "progress", doc), []byte(`{"v":1,"u":1,"d":{}}`), nil)
	a.expect(200, "PUT", "/v1/g/"+g+"/d/progress/"+doc, envb, map[string]string{"If-Match": "0"})
	got := a.expect(200, "GET", "/v1/g/"+g+"/d/progress/"+doc, nil, nil)
	if !bytes.Equal(got, envb) {
		t.Fatal("envelope altered")
	}
	rec := httptest.NewRecorder()
	e.srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `sync_groups{instance="iptv"} 1`) || !strings.Contains(rec.Body.String(), "sync_up") {
		t.Fatalf("metrics: %s", rec.Body.String())
	}
}
