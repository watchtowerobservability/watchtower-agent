package netflow

import (
	"net/netip"
	"testing"
)

// TestRDNSCacheEvictsLRU checks the reverse-DNS cache caps at maxRDNS by evicting the
// least-recently-used host rather than clearing everything, and serves hits without re-resolving.
func TestRDNSCacheEvictsLRU(t *testing.T) {
	var calls int
	e := NewEnricher(nil, nil, func(a netip.Addr) string {
		calls++
		return a.String()
	})
	addr := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
	}
	for i := 0; i < maxRDNS; i++ {
		e.host(addr(i))
	}
	if len(e.cache) != maxRDNS {
		t.Fatalf("cache size = %d, want %d", len(e.cache), maxRDNS)
	}
	// addr(0) is the oldest; touch it so addr(1) becomes least-recently-used, then overflow.
	e.host(addr(0))
	e.host(addr(maxRDNS))
	if len(e.cache) != maxRDNS {
		t.Fatalf("cache size after overflow = %d, want %d", len(e.cache), maxRDNS)
	}
	if _, ok := e.cache[addr(1)]; ok {
		t.Fatal("addr(1) should have been evicted as least-recently-used")
	}
	if _, ok := e.cache[addr(0)]; !ok {
		t.Fatal("addr(0) was touched and must survive eviction")
	}
	before := calls
	if got := e.host(addr(0)); got != addr(0).String() {
		t.Fatalf("host(addr0) = %q", got)
	}
	if calls != before {
		t.Fatalf("expected a cache hit, resolver called %d extra times", calls-before)
	}
}
