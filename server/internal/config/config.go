// Package config reads the server configuration from the environment.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Instance       string // iptv | banking | aiteam
	Listen         string
	MetricsListen  string // "" disables /metrics
	DBPath         string
	BlobDir        string
	Collections    map[string]bool // nil = any [a-z0-9_-]{1,32}
	AdminTokenHash string          // hex sha256; when set, group creation needs the bearer token
	Community      bool            // public ratings enabled
	PowBits        int
	RatingMin      float64
	RatingMax      float64
	MaxDocSize     int64
	MaxDocs        int
	MaxBytes       int64
	MaxBlobSize    int64
	WritesPerMin   int
	CreatesPerDay  int
	VotesPerMin    int
	RetentionDays  int
	TrustProxy     bool
	RealIPHeader   string
	JoinTokenTTL   time.Duration

	ReqsPerMin        int // all requests, per client address
	MaxStreamsDevice  int
	MaxStreamsGroup   int
	MaxStreamDuration time.Duration
	MaxMembers        int
	MaxActiveTokens   int
	MaxRowsFactor     int // docs rows (live + tombstones) <= factor * MaxDocs
	MaxBlobs          int
	BlobMinCost       int64
	TombstoneDays     int
	ChangesMaxBytes   int64
	MaxInFlight       int
	VotesPerDay       int
	MaxRatings        int
	AdminFailsPerHour int
	TrustedProxies    []*net.IPNet
	OpenRegistration  bool
}

var defaultMaxDocs = map[string]int{"iptv": 20000, "banking": 20000, "aiteam": 50000}

// defaultMaxBytesMiB: conversation history (one document per message) needs room.
var defaultMaxBytesMiB = map[string]int{"iptv": 64, "banking": 64, "aiteam": 256}

var defaultCollections = map[string]string{
	"iptv": "profiles,progress,ratings,favorites,lists,order,sources,prefs",
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return d, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

func Load() (*Config, error) {
	c := &Config{
		Instance:       env("SYNC_INSTANCE", ""),
		Listen:         env("SYNC_LISTEN", ":8080"),
		MetricsListen:  env("SYNC_METRICS_LISTEN", ""),
		DBPath:         env("SYNC_DB", "/data/sync.db"),
		BlobDir:        env("SYNC_BLOB_DIR", "/data/blobs"),
		AdminTokenHash: strings.ToLower(env("SYNC_ADMIN_TOKEN_SHA256", "")),
		RealIPHeader:   env("SYNC_REAL_IP_HEADER", "X-Real-IP"),
		TrustProxy:     env("SYNC_TRUST_PROXY", "false") == "true",
		JoinTokenTTL:   10 * time.Minute,
		RatingMin:      0,
		RatingMax:      10,
	}
	switch c.Instance {
	case "iptv", "banking", "aiteam":
	default:
		return nil, fmt.Errorf("SYNC_INSTANCE must be iptv, banking or aiteam (got %q)", c.Instance)
	}
	cols := env("SYNC_COLLECTIONS", defaultCollections[c.Instance])
	if cols != "" && cols != "*" {
		c.Collections = map[string]bool{}
		for _, x := range strings.Split(cols, ",") {
			c.Collections[strings.TrimSpace(x)] = true
		}
	}
	c.Community = c.Instance == "iptv" && env("SYNC_COMMUNITY", "true") == "true"
	var err error
	for _, p := range []struct {
		dst *int
		k   string
		d   int
	}{
		{&c.PowBits, "SYNC_POW_BITS", 16},
		{&c.MaxDocs, "SYNC_MAX_DOCS", defaultMaxDocs[c.Instance]},
		{&c.WritesPerMin, "SYNC_WRITES_PER_MIN", 120},
		{&c.CreatesPerDay, "SYNC_CREATES_PER_DAY", 20},
		{&c.VotesPerMin, "SYNC_VOTES_PER_MIN", 30},
		{&c.RetentionDays, "SYNC_RETENTION_DAYS", 365},
		{&c.ReqsPerMin, "SYNC_REQS_PER_MIN", 600},
		{&c.MaxStreamsDevice, "SYNC_MAX_STREAMS_PER_DEVICE", 3},
		{&c.MaxStreamsGroup, "SYNC_MAX_STREAMS_PER_GROUP", 20},
		{&c.MaxMembers, "SYNC_MAX_MEMBERS", 50},
		{&c.MaxActiveTokens, "SYNC_MAX_ACTIVE_TOKENS", 5},
		{&c.MaxRowsFactor, "SYNC_MAX_ROWS_FACTOR", 2},
		{&c.MaxBlobs, "SYNC_MAX_BLOBS", 200},
		{&c.TombstoneDays, "SYNC_TOMBSTONE_DAYS", 180},
		{&c.MaxInFlight, "SYNC_MAX_IN_FLIGHT", 256},
		{&c.VotesPerDay, "SYNC_VOTES_PER_DAY", 2000},
		{&c.MaxRatings, "SYNC_MAX_RATINGS", 5000000},
		{&c.AdminFailsPerHour, "SYNC_ADMIN_FAILS_PER_HOUR", 10},
	} {
		if *p.dst, err = envInt(p.k, p.d); err != nil {
			return nil, err
		}
	}
	mb, err := envInt("SYNC_MAX_BYTES_MIB", defaultMaxBytesMiB[c.Instance])
	if err != nil {
		return nil, err
	}
	c.MaxBytes = int64(mb) << 20
	c.MaxStreamDuration = time.Hour
	c.BlobMinCost = 4096
	c.ChangesMaxBytes = 4 << 20
	c.OpenRegistration = env("SYNC_OPEN_REGISTRATION", "false") == "true"
	if c.TrustProxy {
		list := env("SYNC_TRUSTED_PROXIES", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
		for _, x := range strings.Split(list, ",") {
			_, n, err := net.ParseCIDR(strings.TrimSpace(x))
			if err != nil {
				return nil, fmt.Errorf("SYNC_TRUSTED_PROXIES: %w", err)
			}
			c.TrustedProxies = append(c.TrustedProxies, n)
		}
	}
	kb, err := envInt("SYNC_MAX_DOC_KIB", 256)
	if err != nil {
		return nil, err
	}
	c.MaxDocSize = int64(kb) << 10
	bm, err := envInt("SYNC_MAX_BLOB_MIB", 16)
	if err != nil {
		return nil, err
	}
	c.MaxBlobSize = int64(bm) << 20
	return c, nil
}
