package proto

import (
	"crypto/sha256"
	"net/url"
	"strings"
)

// NormalizeServer canonicalises a source server URL (IPTV-DATA.md §2):
// lowercase scheme and host, default port dropped, no query/fragment, trailing
// slashes removed from the path. Input without a scheme is treated as http.
func NormalizeServer(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "/"))
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host + strings.TrimRight(u.EscapedPath(), "/")
}

// SourceKey is base64url(SHA-256(kind|server|user)[0..12]) (IPTV-DATA.md §2).
// For Xtream: kind "xtream", server = NormalizeServer(serverUrl), user as typed.
// For M3U: kind "m3u", server = the full URL as typed (trimmed), user "".
func SourceKey(kind, server, user string) string {
	h := sha256.Sum256([]byte(kind + "|" + server + "|" + user))
	return B64(h[:12])
}
