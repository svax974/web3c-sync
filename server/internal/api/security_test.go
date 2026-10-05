package api

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"web3c.cc/sync/internal/config"
	"web3c.cc/sync/internal/proto"
)

// Regression tests for the 2026-10-05 security review (spec/SECURITY-REVIEW.md).

func TestSecPreAuthDoesNotBufferBodies(t *testing.T) {
	e := newEnv(t, nil)
	owner := e.newDev()
	g := gid(21)
	owner.createGroup(g)
	path := "/v1/g/" + g + "/b/x"
	big := bytes.Repeat([]byte{1}, int(e.cfg.MaxBlobSize)+4096)

	// Anonymous: no auth headers at all → refused before the body is read.
	req, _ := http.NewRequest("PUT", e.ts.URL+path, bytes.NewReader(big))
	res, err := http.DefaultClient.Do(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatalf("anonymous oversize PUT: %d", res.StatusCode)
		}
	}
	// A stranger with a valid-looking signature: not a member → 403, body never read.
	stranger := e.newDev()
	if res, _ := stranger.do("PUT", path, big, nil); res.StatusCode != 403 {
		t.Fatalf("non-member oversize PUT: %d", res.StatusCode)
	}
	// A member declaring more than the cap is refused on Content-Length alone.
	if res, _ := owner.do("PUT", path, big, nil); res.StatusCode != 413 {
		t.Fatalf("member oversize PUT: %d", res.StatusCode)
	}
}

func TestSecNonMembersDoNotFillNonceCache(t *testing.T) {
	e := newEnv(t, nil)
	owner := e.newDev()
	g := gid(22)
	owner.createGroup(g)
	before := len(e.srv.nonces.m)
	for i := 0; i < 200; i++ {
		d := e.newDev()
		if res, _ := d.do("GET", "/v1/g/"+g+"/info", nil, nil); res.StatusCode != 403 {
			t.Fatalf("stranger: %d", res.StatusCode)
		}
	}
	if got := len(e.srv.nonces.m); got != before {
		t.Fatalf("nonce cache grew by %d entries for non-members", got-before)
	}
}

func TestSecNonceCacheIsBounded(t *testing.T) {
	c := newNonceCache()
	now := time.Now()
	for i := 0; i < maxNonces; i++ {
		c.m["k"+strconv.Itoa(i)] = now
	}
	if _, full := c.seen("new", now, time.Minute); !full {
		t.Fatal("a saturated nonce cache must refuse, not grow")
	}
	if dup, _ := c.seen("k1", now, time.Minute); !dup {
		t.Fatal("known nonces must still be detected when full")
	}
}

func TestSecNonCanonicalDeviceKeyRejected(t *testing.T) {
	e := newEnv(t, nil)
	d := e.newDev()
	g := gid(23)
	d.createGroup(g)
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := d.b64[len(d.b64)-1]
	idx := strings.IndexByte(alpha, last)
	variant := d.b64[:len(d.b64)-1] + string(alpha[idx^1]) // same key bytes, different padding bits
	if variant == d.b64 {
		t.Fatal("test bug")
	}
	d2 := *d
	d2.b64 = variant
	if res, _ := d2.do("GET", "/v1/g/"+g+"/info", nil, nil); res.StatusCode != 401 {
		t.Fatalf("non-canonical device encoding accepted: %d", res.StatusCode)
	}
}

func openStream(t *testing.T, d *dev, g string, since int64) (*http.Response, *bufio.Reader) {
	t.Helper()
	path := "/v1/g/" + g + "/stream?since=" + strconv.FormatInt(since, 10)
	nonce := make([]byte, 16)
	rand.Read(nonce)
	ts, nn := strconv.FormatInt(time.Now().Unix(), 10), proto.B64(nonce)
	req, _ := http.NewRequest("GET", d.e.ts.URL+path, nil)
	req.Header.Set("X-Device", d.b64)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nn)
	req.Header.Set("X-Signature", proto.Sign(d.priv, proto.Canonical("GET", path, ts, nn, proto.BodyHash(nil), instance)))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res, bufio.NewReader(res.Body)
}

func TestSecRevokedDeviceStreamIsClosed(t *testing.T) {
	e := newEnv(t, nil)
	owner, b := e.newDev(), e.newDev()
	g := gid(24)
	owner.createGroup(g)
	b.joinWith(owner, g)
	res, rd := openStream(t, b, g, 0)
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("stream: %d", res.StatusCode)
	}
	owner.expect(204, "DELETE", "/v1/g/"+g+"/members/"+b.b64, nil, nil)
	owner.expect(200, "PUT", "/v1/g/"+g+"/d/progress/"+docid(1), []byte("x"), map[string]string{"If-Match": "0"})

	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, rd) // returns when the server closes the stream
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked device still holds an open stream")
	}
}

func TestSecStreamCaps(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxStreamsDevice = 2; c.MaxStreamsGroup = 3 })
	owner, b := e.newDev(), e.newDev()
	g := gid(25)
	owner.createGroup(g)
	b.joinWith(owner, g)
	var open []*http.Response
	defer func() {
		for _, r := range open {
			r.Body.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		r, _ := openStream(t, owner, g, 0)
		if r.StatusCode != 200 {
			t.Fatalf("stream %d: %d", i, r.StatusCode)
		}
		open = append(open, r)
	}
	r, _ := openStream(t, owner, g, 0)
	if r.StatusCode != 429 {
		t.Fatalf("per-device cap not enforced: %d", r.StatusCode)
	}
	r.Body.Close()
	r, _ = openStream(t, b, g, 0)
	if r.StatusCode != 200 {
		t.Fatalf("other device: %d", r.StatusCode)
	}
	open = append(open, r)
	r, _ = openStream(t, b, g, 0)
	if r.StatusCode != 429 {
		t.Fatalf("per-group cap not enforced: %d", r.StatusCode)
	}
	r.Body.Close()
}

func TestSecStreamNeverLosesAnEvent(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxDocs = 2000; c.MaxBytes = 8 << 20 })
	owner := e.newDev()
	g := gid(26)
	owner.createGroup(g)
	devs := []*dev{owner}
	for i := 0; i < 5; i++ {
		d := e.newDev()
		d.joinWith(owner, g)
		devs = append(devs, d)
	}
	res, rd := openStream(t, owner, g, 0)
	defer res.Body.Close()

	const per = 40
	var wg sync.WaitGroup
	for di, d := range devs {
		wg.Add(1)
		go func(di int, d *dev) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				id := docid(byte(di*per + i + 1))
				d.do("PUT", "/v1/g/"+g+"/d/progress/"+id, []byte("x"), map[string]string{"If-Match": "0"})
			}
		}(di, d)
	}
	wg.Wait()
	total := int64(len(devs) * per)

	seen := map[int64]bool{}
	deadline := time.Now().Add(15 * time.Second)
	go func() { time.Sleep(time.Until(deadline)); res.Body.Close() }()
	for int64(len(seen)) < total {
		line, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data: ") {
			var ev struct{ Seq int64 }
			json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev)
			seen[ev.Seq] = true
		}
	}
	if int64(len(seen)) != total {
		t.Fatalf("stream delivered %d of %d changes", len(seen), total)
	}
}

func TestSecBlobAccountingMatchesDisk(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxBlobSize = 32 << 10; c.MaxBytes = 4 << 20; c.MaxBlobs = 50 })
	a := e.newDev()
	g := gid(27)
	a.createGroup(g)
	path := "/v1/g/" + g + "/b/race"
	for round := 0; round < 15; round++ {
		var wg sync.WaitGroup
		for i := 1; i <= 12; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				a.do("PUT", path, bytes.Repeat([]byte{byte(n)}, n*1000), nil)
			}(i)
		}
		wg.Wait()
		res, body := a.do("GET", path, nil, nil)
		if res.StatusCode != 200 {
			t.Fatalf("get: %d", res.StatusCode)
		}
		var info struct{ Bytes int64 }
		json.Unmarshal(a.expect(200, "GET", "/v1/g/"+g+"/info", nil, nil), &info)
		want := int64(len(body))
		if want < e.cfg.BlobMinCost {
			want = e.cfg.BlobMinCost
		}
		if info.Bytes != want {
			t.Fatalf("round %d: accounted %d bytes, file is %d (cost %d)", round, info.Bytes, len(body), want)
		}
		// The body must be one coherent version (a single repeated byte).
		if len(body) > 0 && !bytes.Equal(body, bytes.Repeat(body[:1], len(body))) {
			t.Fatalf("round %d: torn blob", round)
		}
	}
}

func TestSecBlobCountAndMinimumCost(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxBlobs = 5 })
	a := e.newDev()
	g := gid(28)
	a.createGroup(g)
	for i := 0; i < 5; i++ {
		a.expect(204, "PUT", "/v1/g/"+g+"/b/b"+strconv.Itoa(i), []byte("x"), nil)
	}
	if res, _ := a.do("PUT", "/v1/g/"+g+"/b/b9", []byte("x"), nil); res.StatusCode != 429 {
		t.Fatalf("blob count cap: %d", res.StatusCode)
	}
	var info struct{ Bytes int64 }
	json.Unmarshal(a.expect(200, "GET", "/v1/g/"+g+"/info", nil, nil), &info)
	if info.Bytes != 5*e.cfg.BlobMinCost {
		t.Fatalf("one-byte blobs must cost the minimum: %d", info.Bytes)
	}
	a.expect(204, "DELETE", "/v1/g/"+g+"/b/b0", nil, nil)
	a.expect(204, "PUT", "/v1/g/"+g+"/b/b9", []byte("x"), nil) // space freed
}

func TestSecTombstonesCountAgainstRows(t *testing.T) {
	e := newEnv(t, nil) // MaxDocs 5, factor 2 → 10 rows
	a := e.newDev()
	g := gid(29)
	a.createGroup(g)
	for i := byte(1); i <= 10; i++ {
		p := "/v1/g/" + g + "/d/progress/" + docid(i)
		var put struct{ Seq int64 }
		json.Unmarshal(a.expect(200, "PUT", p, []byte("x"), map[string]string{"If-Match": "0"}), &put)
		a.expect(200, "DELETE", p, nil, map[string]string{"If-Match": strconv.FormatInt(put.Seq, 10)})
	}
	// docs=0 but 10 tombstone rows exist: a new document is refused.
	if res, _ := a.do("PUT", "/v1/g/"+g+"/d/progress/"+docid(99), []byte("x"), map[string]string{"If-Match": "0"}); res.StatusCode != 429 {
		t.Fatalf("tombstone growth not bounded: %d", res.StatusCode)
	}
	// Old tombstones are reclaimed by housekeeping.
	if n, err := e.st.PurgeTombstones(time.Now().Add(time.Hour)); err != nil || n != 10 {
		t.Fatalf("purge tombstones: %d %v", n, err)
	}
	a.expect(200, "PUT", "/v1/g/"+g+"/d/progress/"+docid(99), []byte("x"), map[string]string{"If-Match": "0"})
}

func TestSecTokenAndMemberCaps(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxActiveTokens = 2; c.MaxMembers = 3 })
	owner := e.newDev()
	g := gid(30)
	owner.createGroup(g)
	owner.expect(201, "POST", "/v1/g/"+g+"/join-tokens", nil, nil)
	owner.expect(201, "POST", "/v1/g/"+g+"/join-tokens", nil, nil)
	if res, _ := owner.do("POST", "/v1/g/"+g+"/join-tokens", nil, nil); res.StatusCode != 429 {
		t.Fatalf("active token cap: %d", res.StatusCode)
	}
	// Members: the owner + 2 joins fill the group; the next join is refused.
	e2 := newEnv(t, func(c *config.Config) { c.MaxMembers = 3 })
	o2 := e2.newDev()
	g2 := gid(31)
	o2.createGroup(g2)
	o2.expect(200, "GET", "/v1/g/"+g2+"/info", nil, nil)
	e2.newDev().joinWith(o2, g2)
	e2.newDev().joinWith(o2, g2)
	b := o2.expect(201, "POST", "/v1/g/"+g2+"/join-tokens", nil, nil)
	var tok struct{ Token string }
	json.Unmarshal(b, &tok)
	if res, _ := e2.newDev().do("POST", "/v1/g/"+g2+"/join", []byte(`{"token":"`+tok.Token+`","nameEnc":"x"}`), nil); res.StatusCode != 429 {
		t.Fatalf("member cap: %d", res.StatusCode)
	}
}

func TestSecAdminTokenBruteForceIsThrottled(t *testing.T) {
	sum := sha256Sum("secret")
	e := newEnv(t, func(c *config.Config) { c.AdminTokenHash = hexOf(sum[:]); c.AdminFailsPerHour = 3 })
	d := e.newDev()
	for i := 0; i < 3; i++ {
		d.expect(403, "POST", "/v1/g", []byte(`{"groupId":"`+gid(byte(40+i))+`"}`), map[string]string{"Authorization": "Bearer wrong" + strconv.Itoa(i)})
	}
	// Once the budget is spent even the right token is refused for now.
	d.expect(429, "POST", "/v1/g", []byte(`{"groupId":"`+gid(50)+`"}`), map[string]string{"Authorization": "Bearer secret"})
}

func TestSecForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	// Untrusted peer (the test client is 127.0.0.1, not listed): header ignored.
	e := newEnv(t, func(c *config.Config) {
		c.TrustProxy, c.RealIPHeader, c.CreatesPerDay = true, "X-Real-IP", 2
	})
	d := e.newDev()
	for i := 0; i < 2; i++ {
		d.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+gid(byte(60+i))+`"}`), map[string]string{"X-Real-IP": "9.9.9." + strconv.Itoa(i)})
	}
	d.expect(429, "POST", "/v1/g", []byte(`{"groupId":"`+gid(70)+`"}`), map[string]string{"X-Real-IP": "9.9.9.77"})

	// Trusted proxy: the forwarded address is used.
	e2 := newEnv(t, func(c *config.Config) {
		c.TrustProxy, c.RealIPHeader, c.CreatesPerDay = true, "X-Real-IP", 1
		c.TrustedProxies = append(c.TrustedProxies, loop)
	})
	d2 := e2.newDev()
	d2.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+gid(71)+`"}`), map[string]string{"X-Real-IP": "9.9.9.1"})
	d2.expect(201, "POST", "/v1/g", []byte(`{"groupId":"`+gid(72)+`"}`), map[string]string{"X-Real-IP": "9.9.9.2"})
	d2.expect(429, "POST", "/v1/g", []byte(`{"groupId":"`+gid(73)+`"}`), map[string]string{"X-Real-IP": "9.9.9.2"})
}

func TestSecClientIPNormalisation(t *testing.T) {
	_, loop, _ := net.ParseCIDR("::1/128")
	s := &Server{cfg: &config.Config{TrustProxy: true, RealIPHeader: "X-Real-IP", TrustedProxies: []*net.IPNet{loop}}}
	mk := func(remote, hdr string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if hdr != "" {
			r.Header.Set("X-Real-IP", hdr)
		}
		return r
	}
	a := s.clientIP(mk("[2001:db8:1:2::1]:1234", ""))
	b := s.clientIP(mk("[2001:db8:1:2:ffff::9]:1234", ""))
	if a != b {
		t.Fatalf("addresses of one /64 must share a key: %s vs %s", a, b)
	}
	if got := s.clientIP(mk("[::1]:1", "not-an-ip")); got != "::/64" && got == "not-an-ip" {
		t.Fatalf("forwarded value must be validated: %s", got)
	}
	if got := s.clientIP(mk("[2001:db8::1]:1", "1.2.3.4")); strings.Contains(got, "1.2.3.4") {
		t.Fatalf("untrusted peer must not set its address: %s", got)
	}
}

func TestSecRateLimiterTableIsBounded(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	for i := 0; i < maxLimiterKeys; i++ {
		l.m["k"+strconv.Itoa(i)] = &window{start: now, n: 1}
	}
	if l.allow("another", 10, time.Minute, now) {
		t.Fatal("a full limiter must fail closed")
	}
	long := strings.Repeat("a", 5000)
	l2 := newLimiter()
	l2.allow(long, 10, time.Minute, now)
	for k := range l2.m {
		if len(k) > maxKeyLen {
			t.Fatalf("limiter key not capped: %d", len(k))
		}
	}
}

func TestSecReservedCollectionNames(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Collections = nil }) // any collection allowed
	a := e.newDev()
	g := gid(80)
	a.createGroup(g)
	if res, _ := a.do("PUT", "/v1/g/"+g+"/d/_name/"+docid(1), []byte("x"), map[string]string{"If-Match": "0"}); res.StatusCode != 400 {
		t.Fatalf("reserved collection writable: %d", res.StatusCode)
	}
	a.expect(200, "PUT", "/v1/g/"+g+"/d/anything/"+docid(1), []byte("x"), map[string]string{"If-Match": "0"})
}

func TestSecInFlightIsBounded(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxInFlight = 1 })
	block := make(chan struct{})
	slow := httptest.NewServer(e.srv.instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	})))
	defer slow.Close()
	go http.Get(slow.URL + "/v1/x")
	time.Sleep(100 * time.Millisecond)
	res, err := http.Get(slow.URL + "/v1/y")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatalf("saturation must shed load with 503, got %d", res.StatusCode)
	}
	close(block)
}

func TestSecDeviceKeyUnused(t *testing.T) { _ = ed25519.PublicKeySize } // keeps the import honest
