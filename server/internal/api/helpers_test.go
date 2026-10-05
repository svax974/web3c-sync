package api

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }
func hexOf(b []byte) string       { return hex.EncodeToString(b) }
