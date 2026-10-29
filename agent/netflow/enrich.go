package netflow

import (
	"net/netip"
	"slices"
	"strconv"
	"sync"
)

// maxRDNS bounds the reverse-DNS cache; when full it is emptied (shortcut: no LRU, flows repeat
// the same few hosts per minute, upgrade if the hit rate drops).
const maxRDNS = 10_000

// PrefixInfo is what a table says about a prefix: its AS number and country.
type PrefixInfo struct {
	Prefix  netip.Prefix
	ASN     uint32
	Country string
}

// Enricher adds AS, country, reverse DNS and interface names to flow rows. The tables come from
// local config (nothing is fetched); RDNS is injected so the collector chooses a resolver that
// honours its own network policy. A nil *Enricher adds nothing.
type Enricher struct {
	prefixes []PrefixInfo // longest prefix first
	ifNames  map[string]map[uint32]string
	RDNS     func(netip.Addr) string

	mu    sync.Mutex
	cache map[netip.Addr]string
}

// NewEnricher builds an Enricher; ifNames is exporter -> ifIndex -> name (ifName from SNMP).
func NewEnricher(prefixes []PrefixInfo, ifNames map[string]map[uint32]string, rdns func(netip.Addr) string) *Enricher {
	ps := slices.Clone(prefixes)
	slices.SortStableFunc(ps, func(a, b PrefixInfo) int { return b.Prefix.Bits() - a.Prefix.Bits() })
	return &Enricher{prefixes: ps, ifNames: ifNames, RDNS: rdns, cache: map[netip.Addr]string{}}
}

func (e *Enricher) lookup(a netip.Addr) (PrefixInfo, bool) {
	for _, p := range e.prefixes {
		if p.Prefix.Contains(a) {
			return p, true
		}
	}
	return PrefixInfo{}, false
}

func (e *Enricher) host(a netip.Addr) string {
	if e.RDNS == nil {
		return ""
	}
	e.mu.Lock()
	h, ok := e.cache[a]
	e.mu.Unlock()
	if ok {
		return h
	}
	h = e.RDNS(a)
	e.mu.Lock()
	if len(e.cache) >= maxRDNS {
		clear(e.cache)
	}
	e.cache[a] = h
	e.mu.Unlock()
	return h
}

// Apply adds the enrichment attributes of r (exported by exporter) to attrs.
func (e *Enricher) Apply(attrs map[string]string, exporter string, r Row) {
	if e == nil {
		return
	}
	for side, a := range map[string]netip.Addr{"src": r.Src, "dst": r.Dst} {
		if p, ok := e.lookup(a); ok {
			attrs["flow."+side+"_asn"] = strconv.FormatUint(uint64(p.ASN), 10)
			if p.Country != "" {
				attrs["flow."+side+"_country"] = p.Country
			}
		}
		if h := e.host(a); h != "" {
			attrs["flow."+side+"_host"] = h
		}
	}
	if n := e.ifNames[exporter][r.InIf]; n != "" {
		attrs["flow.in_if_name"] = n
	}
	if n := e.ifNames[exporter][r.OutIf]; n != "" {
		attrs["flow.out_if_name"] = n
	}
}
