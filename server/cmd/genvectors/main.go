// genvectors writes spec/vectors/v1.json from fixed inputs. Run:
//   go run ./cmd/genvectors > ../spec/vectors/v1.json
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"

	"web3c.cc/sync/internal/proto"
)

func seq(start, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

func main() {
	kg := seq(0, 32)
	keys := proto.DeriveKeys(kg)
	instance, group, coll := "iptv", "AAAAAAAAAAAAAAAAAAAAAA", "progress"
	logical := "movie_1234"
	docID := proto.DocID(keys.ID, coll, logical)
	aad := proto.AAD(instance, group, coll, docID)
	nonce := seq(0xA0, 12)
	pt := []byte(`{"v":1,"u":1760000000000,"d":{"pos":120,"dur":5400}}`)
	env, _ := proto.Seal(keys.Enc, aad, pt, nonce)

	seed := seq(0x10, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	body := []byte(`{"groupId":"AAAAAAAAAAAAAAAAAAAAAA"}`)
	path := "/v1/g/AAAAAAAAAAAAAAAAAAAAAA/d/progress/" + docID + "?x=1"
	ts, nn := "1760000000", proto.B64(seq(0x30, 16))
	canon := proto.Canonical("PUT", path, ts, nn, proto.BodyHash(body), instance)

	r := 7.5
	pseud := proto.Pseudonym(keys.ID, "profile-1", "movie:tmdb:603")
	n := proto.SolvePow("movie:tmdb:603", pseud, &r, 12)

	padLens := []int{}
	padIn := []int{0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 100, 255, 256, 1000, 4096, 65536}
	for _, l := range padIn {
		padLens = append(padLens, proto.Padme(l))
	}

	out := map[string]any{
		"version": "web3c-sync/v1",
		"hkdf": map[string]any{
			"kg": proto.B64(kg), "enc": proto.B64(keys.Enc),
			"id": proto.B64(keys.ID), "name": proto.B64(keys.Name),
		},
		"docId": map[string]any{
			"collection": coll, "logicalId": logical, "docId": docID,
		},
		"padme": map[string]any{"in": padIn, "out": padLens},
		"seal": map[string]any{
			"instance": instance, "groupId": group, "collection": coll, "docId": docID,
			"plaintext": string(pt), "nonce": proto.B64(nonce),
			"aad": proto.B64(aad), "envelope": proto.B64(env),
		},
		"request": map[string]any{
			"seed": proto.B64(seed), "pub": proto.B64(pub),
			"method": "PUT", "path": path, "timestamp": ts, "nonce": nn,
			"body": string(body), "bodyHash": proto.BodyHash(body), "instance": instance,
			"canonical": string(canon), "signature": proto.Sign(priv, canon),
		},
		"rating": map[string]any{
			"profileId": "profile-1", "contentKey": "movie:tmdb:603", "kUser": "id",
			"pseudonym": pseud, "r": r, "ratingText": proto.RatingText(&r),
			"powBits": 12, "n": n,
			"digest": proto.B64(func() []byte { d := proto.PowDigest("movie:tmdb:603", pseud, &r, n); return d[:] }()),
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
