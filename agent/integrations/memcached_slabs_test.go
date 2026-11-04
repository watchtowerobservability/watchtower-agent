package integrations

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Recorded `stats slabs` and `stats items` replies of memcached 1.6.
const memcachedSlabsFixture = "STAT 1:chunk_size 96\r\nSTAT 1:used_chunks 10\r\nSTAT 1:free_chunks 0\r\nSTAT 1:total_pages 1\r\n" +
	"STAT active_slabs 1\r\nSTAT total_malloced 1048576\r\nEND\r\n" +
	"STAT items:1:number 10\r\nSTAT items:1:age 3600\r\nSTAT items:1:evicted 42\r\nSTAT items:1:evicted_time 12\r\n" +
	"STAT items:1:outofmemory 3\r\nEND\r\n"

func TestMemcachedSlabsAndItems(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(memcachedSlabsFixture))
	slabs, err := ReadMemcachedStats(r)
	if err != nil {
		t.Fatal(err)
	}
	items, err := ReadMemcachedStats(r)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	EmitMemcachedSlabs(rec, slabs, items, time.Now())
	wantNames(t, rec, "memcached.slab.chunk_size", "memcached.slab.chunks.used", "memcached.slab.items",
		"memcached.slab.evictions", "memcached.slab.last_evicted_age", "memcached.slab.out_of_memory")
	for _, s := range rec.Samples {
		if s.Name == "memcached.slab.evictions" && (s.Value != 42 || s.Attrs["slab_class"] != "1") {
			t.Fatalf("%+v", s)
		}
	}
	items["items:1:evicted"] = "0"
	rec2 := &sink.Recorder{}
	EmitMemcachedSlabs(rec2, nil, items, time.Now())
	if rec2.Names()["memcached.slab.last_evicted_age"] {
		t.Fatal("a class that never evicted has no last evicted age")
	}
	if rec.Names()["memcached.slab.active_slabs"] {
		t.Fatal("global slab lines are not per-class series")
	}
}
