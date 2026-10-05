package proto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestPadme(t *testing.T) {
	cases := map[int]int{0: 0, 1: 1, 2: 2, 3: 3, 8: 8, 9: 10, 15: 16, 17: 18, 100: 104, 256: 256, 1000: 1024}
	for in, want := range cases {
		if got := Padme(in); got != want {
			t.Errorf("Padme(%d)=%d want %d", in, got, want)
		}
	}
}

func TestSealOpenRoundTripAndBinding(t *testing.T) {
	k := DeriveKeys(bytes.Repeat([]byte{7}, 32))
	aad := AAD("iptv", "g", "progress", "d")
	for _, n := range []int{0, 1, 5, 100, 5000} {
		pt := bytes.Repeat([]byte{'a'}, n)
		env, err := Seal(k.Enc, aad, pt, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(k.Enc, aad, env)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("n=%d: %v", n, err)
		}
		// Wrong context (other doc / other instance) must fail.
		if _, err := Open(k.Enc, AAD("iptv", "g", "progress", "other"), env); err == nil {
			t.Fatal("AAD docId not bound")
		}
		if _, err := Open(k.Enc, AAD("banking", "g", "progress", "d"), env); err == nil {
			t.Fatal("AAD instance not bound")
		}
		// Tampering and version byte.
		bad := append([]byte{}, env...)
		bad[len(bad)-1] ^= 1
		if _, err := Open(k.Enc, aad, bad); err == nil {
			t.Fatal("tamper accepted")
		}
		bad = append([]byte{}, env...)
		bad[0] = 2
		if _, err := Open(k.Enc, aad, bad); err == nil {
			t.Fatal("unknown version accepted")
		}
	}
}

func TestFieldsAreUnambiguous(t *testing.T) {
	if bytes.Equal(fields("ab", "c"), fields("a", "bc")) {
		t.Fatal("ambiguous")
	}
	if DocID(bytes.Repeat([]byte{1}, 32), "ab", "c") == DocID(bytes.Repeat([]byte{1}, 32), "a", "bc") {
		t.Fatal("docId collision across collection/logical split")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := Canonical("GET", "/v1/x", "1", "n", BodyHash(nil), "iptv")
	sig := Sign(priv, c)
	if !Verify(pub, c, sig) {
		t.Fatal("verify")
	}
	if Verify(pub, Canonical("GET", "/v1/y", "1", "n", BodyHash(nil), "iptv"), sig) {
		t.Fatal("path not bound")
	}
	if BodyHash(nil) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("empty hash")
	}
}

func TestPow(t *testing.T) {
	r := 4.0
	n := SolvePow("movie:tmdb:1", "p", &r, 10)
	if !PowOK("movie:tmdb:1", "p", &r, n, 10) {
		t.Fatal("pow")
	}
	r2 := 5.0
	if PowOK("movie:tmdb:1", "p", &r2, n, 10) && PowOK("movie:tmdb:1", "p", &r2, n, 20) {
		t.Fatal("pow not bound to rating")
	}
}

func TestRatingText(t *testing.T) {
	a, b := 7.0, 7.5
	if RatingText(&a) != "7" || RatingText(&b) != "7.5" || RatingText(nil) != "null" {
		t.Fatal("rating text")
	}
}
