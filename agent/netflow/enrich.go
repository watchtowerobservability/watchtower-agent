package netflow

import (
	"container/list"
	"net/netip"
	"slices"
	"strconv"
	"sync"
)

// maxRDNS bounds the reverse-DNS cache; the least-recently-used host is evicted when it is full.
const maxRDNS = 10_000

// PrefixInfo is what a table says about a prefix: its AS number, country and availability
// zone (a subnet lives in one zone in AWS, GCP and Azure).
type PrefixInfo struct {
	Prefix  netip.Prefix
	ASN     uint32
	Country string
	Zone    string
}

// Enricher adds AS, country, reverse DNS and interface names to flow rows. The tables come from
// local config (nothing is fetched); RDNS is injected so the collector chooses a resolver that
// honours its own network policy. A nil *Enricher adds nothing.
type Enricher struct {
	prefixes []PrefixInfo // longest prefix first
	ifNames  map[string]map[uint32]string
	RDNS     func(netip.Addr) string

	mu    sync.Mutex
	lru   *list.List                   // front = most recently used
	cache map[netip.Addr]*list.Element // addr -> element holding *rdnsEntry
}

// rdnsEntry is one cached reverse-DNS answer, carried by an lru list element.
type rdnsEntry struct {
	addr netip.Addr
	host string
}

// NewEnricher builds an Enricher; ifNames is exporter -> ifIndex -> name (ifName from SNMP).
func NewEnricher(prefixes []PrefixInfo, ifNames map[string]map[uint32]string, rdns func(netip.Addr) string) *Enricher {
	ps := slices.Clone(prefixes)
	slices.SortStableFunc(ps, func(a, b PrefixInfo) int { return b.Prefix.Bits() - a.Prefix.Bits() })
	return &Enricher{prefixes: ps, ifNames: ifNames, RDNS: rdns, lru: list.New(), cache: map[netip.Addr]*list.Element{}}
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
	if el, ok := e.cache[a]; ok {
		e.lru.MoveToFront(el)
		h := el.Value.(*rdnsEntry).host
		e.mu.Unlock()
		return h
	}
	e.mu.Unlock()
	// Resolve outside the lock so a slow lookup never blocks other flows.
	h := e.RDNS(a)
	e.mu.Lock()
	if el, ok := e.cache[a]; ok { // another flow resolved it meanwhile
		e.lru.MoveToFront(el)
		el.Value.(*rdnsEntry).host = h
	} else {
		e.cache[a] = e.lru.PushFront(&rdnsEntry{addr: a, host: h})
		for e.lru.Len() > maxRDNS {
			back := e.lru.Back()
			e.lru.Remove(back)
			delete(e.cache, back.Value.(*rdnsEntry).addr)
		}
	}
	e.mu.Unlock()
	return h
}

// Apply adds the enrichment attributes of r (exported by exporter) to attrs.
func (e *Enricher) Apply(attrs map[string]string, exporter string, r Row) {
	if e == nil {
		return
	}
	zones := map[string]string{}
	for side, a := range map[string]netip.Addr{"src": r.Src, "dst": r.Dst} {
		if p, ok := e.lookup(a); ok {
			if p.ASN != 0 {
				attrs["flow."+side+"_asn"] = strconv.FormatUint(uint64(p.ASN), 10)
			}
			if p.Country != "" {
				attrs["flow."+side+"_country"] = p.Country
			}
			if p.Zone != "" {
				attrs["flow."+side+"_zone"] = p.Zone
				zones[side] = p.Zone
			}
		}
		if h := e.host(a); h != "" {
			attrs["flow."+side+"_host"] = h
		}
	}
	// Inter-zone traffic (CFT-E12): known on both ends, so cross-AZ bytes can be summed.
	if zones["src"] != "" && zones["dst"] != "" {
		attrs["flow.cross_zone"] = strconv.FormatBool(zones["src"] != zones["dst"])
	}
	if n := e.ifNames[exporter][r.InIf]; n != "" {
		attrs["flow.in_if_name"] = n
	}
	if n := e.ifNames[exporter][r.OutIf]; n != "" {
		attrs["flow.out_if_name"] = n
	}
}
