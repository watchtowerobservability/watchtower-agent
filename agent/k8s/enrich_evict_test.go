package k8s

import (
	"testing"
	"time"
)

func TestEvictOwnersDropsExpiredThenOldest(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	// Below the cap: nothing is touched.
	cache := map[string]cachedOwner{"a": {at: now}}
	evictOwners(cache, 3, now)
	if len(cache) != 1 {
		t.Fatalf("below cap must not evict, got %d", len(cache))
	}

	// Full, with one expired entry: the expired one goes, the fresh ones stay.
	cache = map[string]cachedOwner{
		"stale": {at: now.Add(-ownerTTL - time.Minute)},
		"b":     {at: now.Add(-time.Minute)},
		"c":     {at: now},
	}
	evictOwners(cache, 3, now)
	if _, ok := cache["stale"]; ok {
		t.Fatalf("expired entry must be evicted")
	}
	if len(cache) != 2 {
		t.Fatalf("want 2 after dropping the expired entry, got %d", len(cache))
	}

	// Full and every entry fresh: only the single oldest is dropped.
	cache = map[string]cachedOwner{
		"old": {at: now.Add(-3 * time.Minute)},
		"mid": {at: now.Add(-2 * time.Minute)},
		"new": {at: now.Add(-time.Minute)},
	}
	evictOwners(cache, 3, now)
	if len(cache) != 2 {
		t.Fatalf("want 2 after dropping the oldest fresh entry, got %d", len(cache))
	}
	if _, ok := cache["old"]; ok {
		t.Fatalf("oldest fresh entry must be evicted, not a newer one")
	}
}
