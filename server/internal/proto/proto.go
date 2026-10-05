// Package proto is the reference implementation of the web3c-sync v1
// cryptographic and wire primitives (see spec/PROTOCOL.md). The server uses it
// for request authentication and proof-of-work checks; the vector generator
// uses it to produce spec/vectors/v1.json, which every client must reproduce.
package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/bits"
	"strconv"
)

const (
	Version    = "web3c-sync/v1"
	EnvVersion = 0x01
	nonceLen   = 12
	tagLen     = 16
)

var b64 = base64.RawURLEncoding

func B64(b []byte) string            { return b64.EncodeToString(b) }
func UnB64(s string) ([]byte, error) { return b64.DecodeString(s) }

// Field encodes x as u16(len) || x (anti-ambiguity length prefix).
func Field(x []byte) []byte {
	out := make([]byte, 2+len(x))
	binary.BigEndian.PutUint16(out, uint16(len(x)))
	copy(out[2:], x)
	return out
}

func fields(parts ...string) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, Field([]byte(p))...)
	}
	return out
}

// hkdf implements RFC 5869 HKDF-SHA256 for L <= 32 (single block).
func hkdf(ikm, salt []byte, info string, l int) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	exp := hmac.New(sha256.New, prk)
	exp.Write([]byte(info))
	exp.Write([]byte{1})
	return exp.Sum(nil)[:l]
}

// Keys holds the keys derived from the group secret K_g.
type Keys struct{ Enc, ID, Name, Rating []byte }

func DeriveKeys(kg []byte) Keys {
	salt := []byte(Version)
	return Keys{
		Enc:  hkdf(kg, salt, "enc", 32),
		ID:   hkdf(kg, salt, "id", 32),
		Name: hkdf(kg, salt, "name", 32),
		// Dedicated to public-rating pseudonyms: never reuse K_id for another purpose.
		Rating: hkdf(kg, salt, "rating", 32),
	}
}

// DocID is the pseudonymised document identifier (§4).
func DocID(kID []byte, collection, logicalID string) string {
	m := hmac.New(sha256.New, kID)
	m.Write(fields(collection, logicalID))
	return B64(m.Sum(nil))
}

// Padme returns the padded length for l (§3).
func Padme(l int) int {
	if l < 2 {
		return l
	}
	e := bits.Len(uint(l)) - 1
	s := bits.Len(uint(e))
	z := e - s
	mask := (1 << z) - 1
	return (l + mask) &^ mask
}

func pad(p []byte) []byte {
	n := Padme(len(p) + 1)
	m := make([]byte, n)
	copy(m, p)
	m[len(p)] = 0x80
	return m
}

func unpad(m []byte) ([]byte, error) {
	i := len(m) - 1
	for i >= 0 && m[i] == 0 {
		i--
	}
	if i < 0 || m[i] != 0x80 {
		return nil, ErrDecrypt
	}
	return m[:i], nil
}

// AAD binds a ciphertext to its context (§3).
func AAD(instance, groupID, collection, docID string) []byte {
	out := append([]byte(Version), 0)
	return append(out, fields(instance, groupID, collection, docID)...)
}

var ErrDecrypt = errors.New("decrypt")

// Seal encrypts plaintext into an envelope (§3). nonce may be nil (random);
// tests pass a fixed nonce for the vectors.
func Seal(kEnc []byte, aad, plaintext, nonce []byte) ([]byte, error) {
	if nonce == nil {
		nonce = make([]byte, nonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	blk, err := aes.NewCipher(kEnc)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	out := append([]byte{EnvVersion}, nonce...)
	return g.Seal(out, nonce, pad(plaintext), aad), nil
}

// Open decrypts an envelope.
func Open(kEnc []byte, aad, env []byte) ([]byte, error) {
	if len(env) < 1+nonceLen+tagLen+1 || env[0] != EnvVersion {
		return nil, ErrDecrypt
	}
	blk, err := aes.NewCipher(kEnc)
	if err != nil {
		return nil, ErrDecrypt
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, ErrDecrypt
	}
	m, err := g.Open(nil, env[1:1+nonceLen], env[1+nonceLen:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return unpad(m)
}

// BodyHash is lowercase hex SHA-256 of the request body.
func BodyHash(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// Canonical builds the signed string for a request (§5).
func Canonical(method, pathQuery, timestamp, nonce, bodyHash, instance string) []byte {
	return []byte(Version + "\n" + method + "\n" + pathQuery + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash + "\n" + instance)
}

func Sign(priv ed25519.PrivateKey, canonical []byte) string {
	return B64(ed25519.Sign(priv, canonical))
}

func Verify(pub ed25519.PublicKey, canonical []byte, sigB64 string) bool {
	sig, err := UnB64(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, canonical, sig)
}

// RatingText is the shortest decimal text of r ("7", "7.5"), or "null".
func RatingText(r *float64) string {
	if r == nil {
		return "null"
	}
	return strconv.FormatFloat(*r, 'f', -1, 64)
}

// PowDigest is SHA-256(field(contentKey) || field(p) || canonical(r) || u64(t) || u64(n)) (§9).
func PowDigest(contentKey, pseudonym string, r *float64, t int64, n uint64) [32]byte {
	var buf bytes.Buffer
	buf.Write(Field([]byte(contentKey)))
	buf.Write(Field([]byte(pseudonym)))
	buf.WriteString(RatingText(r))
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(t))
	buf.Write(u[:])
	binary.BigEndian.PutUint64(u[:], n)
	buf.Write(u[:])
	return sha256.Sum256(buf.Bytes())
}

func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

func PowOK(contentKey, pseudonym string, r *float64, t int64, n uint64, powBits int) bool {
	return leadingZeroBits(PowDigest(contentKey, pseudonym, r, t, n)) >= powBits
}

// SolvePow finds the smallest n satisfying the proof of work.
func SolvePow(contentKey, pseudonym string, r *float64, t int64, powBits int) uint64 {
	for n := uint64(0); ; n++ {
		if PowOK(contentKey, pseudonym, r, t, n, powBits) {
			return n
		}
	}
}

// Pseudonym = HMAC(kRating, field("rating") || field(profileID) || field(contentKey)) (§9).
func Pseudonym(kRating []byte, profileID, contentKey string) string {
	m := hmac.New(sha256.New, kRating)
	m.Write(fields("rating", profileID, contentKey))
	return B64(m.Sum(nil))
}

func ValidRating(r float64, min, max float64) bool {
	return !math.IsNaN(r) && !math.IsInf(r, 0) && r >= min && r <= max
}
