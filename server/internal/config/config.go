// Package config reads the server configuration from the environment.
package config

import (
	"fmt"
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
}

var defaultCollections = map[string]string{
	"iptv": "profiles,progress,ratings,favorites,lists,order,sources,prefs,_name",
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
		{&c.MaxDocs, "SYNC_MAX_DOCS", 5000},
		{&c.WritesPerMin, "SYNC_WRITES_PER_MIN", 120},
		{&c.CreatesPerDay, "SYNC_CREATES_PER_DAY", 20},
		{&c.VotesPerMin, "SYNC_VOTES_PER_MIN", 30},
		{&c.RetentionDays, "SYNC_RETENTION_DAYS", 365},
	} {
		if *p.dst, err = envInt(p.k, p.d); err != nil {
			return nil, err
		}
	}
	mb, err := envInt("SYNC_MAX_BYTES_MIB", 64)
	if err != nil {
		return nil, err
	}
	c.MaxBytes = int64(mb) << 20
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
