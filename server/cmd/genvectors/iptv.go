package main

import "web3c.cc/sync/internal/proto"

type srcCase struct {
	Kind, Server, User string
}

// iptvVectors feeds spec/vectors/iptv-v1.json.
func iptvVectors() map[string]any {
	norm := []string{
		"http://Example.COM:80/", "https://Example.com:443", "example.com:8080/",
		"HTTP://host.tld:8000///", "http://1.2.3.4/xc", "  http://srv.tld/panel/  ",
		"https://srv.tld:8443/a/b/", "srv.tld",
	}
	var normOut []map[string]string
	for _, n := range norm {
		normOut = append(normOut, map[string]string{"in": n, "out": proto.NormalizeServer(n)})
	}
	cases := []srcCase{
		{"xtream", "http://Example.COM:80/", "Bob"},
		{"xtream", "https://srv.tld:8443/a/", "alice"},
		{"m3u", "http://x.tld/get.php?username=a&password=b&type=m3u", ""},
	}
	var keys []map[string]string
	for _, c := range cases {
		server := c.Server
		if c.Kind == "xtream" {
			server = proto.NormalizeServer(c.Server)
		}
		keys = append(keys, map[string]string{
			"kind": c.Kind, "server": c.Server, "user": c.User,
			"sourceKey": proto.SourceKey(c.Kind, server, c.User),
		})
	}
	return map[string]any{"normalizeServer": normOut, "sourceKey": keys, "doneThreshold": 0.9}
}
