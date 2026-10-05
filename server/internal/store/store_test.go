package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:", filepath.Join(t.TempDir(), "b"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInactivePurgeCountsTouch(t *testing.T) {
	s := newStore(t)
	base := time.Now()
	s.now = func() time.Time { return base }
	if err := s.CreateGroup("g1", "pub", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateGroup("g2", "pub2", ""); err != nil {
		t.Fatal(err)
	}
	// A year later g1 has only been read (Touch), g2 is untouched.
	s.now = func() time.Time { return base.Add(364 * 24 * time.Hour) }
	s.Touch("g1")
	s.now = func() time.Time { return base.Add(366 * 24 * time.Hour) }
	ids, err := s.PurgeInactive(s.now().Add(-365 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "g2" {
		t.Fatalf("purged %v, want only the untouched group", ids)
	}
	if _, err := s.Info("g1"); err != nil {
		t.Fatalf("group read within the year was purged: %v", err)
	}
}

func TestStaleRatingNeverReplacesNewer(t *testing.T) {
	s := newStore(t)
	r9, r2 := 9.0, 2.0
	if err := s.PutRating("movie:tmdb:1", "p", &r9, 100, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRating("movie:tmdb:1", "p", &r2, 99, 10); err != ErrStale {
		t.Fatalf("older vote accepted: %v", err)
	}
	if err := s.PutRating("movie:tmdb:1", "p", &r2, 100, 10); err != ErrStale {
		t.Fatalf("equal timestamp accepted: %v", err)
	}
	if err := s.PutRating("movie:tmdb:2", "p", &r2, 1, 1); err != ErrFull {
		t.Fatalf("table cap not enforced: %v", err)
	}
	a, _ := s.Aggregates([]string{"movie:tmdb:1"})
	if a["movie:tmdb:1"].Sum != 9 {
		t.Fatalf("aggregate: %+v", a)
	}
}
