package config

import "testing"

func TestIptvDefaultCollections(t *testing.T) {
	t.Setenv("SYNC_INSTANCE", "iptv")
	t.Setenv("SYNC_COLLECTIONS", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// tmdbcache: the answers TMDB gave, shared by the devices of a group.
	for _, want := range []string{"profiles", "progress", "ratings", "favorites", "lists", "order", "sources", "prefs", "tmdbcache"} {
		if !c.Collections[want] {
			t.Errorf("collection %q not allowed by default on iptv", want)
		}
	}
	if c.Collections["messages"] {
		t.Error("unexpected collection allowed on iptv")
	}
}
