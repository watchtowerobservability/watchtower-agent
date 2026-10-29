package netpath

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Probe protocols.
const (
	ProtoTCP = "tcp" // SYN with a rising TTL; works where ICMP echo and UDP are filtered
	ProtoUDP = "udp"
)

const (
	// MaxPaths bounds the source ports tried per trace (equal-cost multipath discovery).
	MaxPaths = 16
	maxHops  = 30
)

// Result is what one probe learned.
type Result struct {
	Addr    netip.Addr // zero when nobody answered
	RTT     time.Duration
	Reached bool // the destination itself answered
}

// Prober sends one probe with the given TTL from the given source port. Varying the source port
// changes the flow hash, which is how equal-cost paths are told apart.
type Prober interface {
	Probe(ctx context.Context, ttl int, srcPort uint16) Result
}

// Hop is one TTL step.
type Hop struct {
	TTL   int     `json:"ttl"`
	Addr  string  `json:"addr,omitempty"`
	RTTMS float64 `json:"rtt_ms,omitempty"`
	Lost  bool    `json:"lost,omitempty"`
}

// Path is the hops of one trace.
type Path struct {
	SrcPort uint16 `json:"src_port"`
	Hops    []Hop  `json:"hops"`
	Reached bool   `json:"reached"`
}

// Signature identifies a path by its router addresses (a silent hop is "*"), so two traces of
// the same route compare equal whatever their round trip times.
func (p Path) Signature() string {
	a := make([]string, len(p.Hops))
	for i, h := range p.Hops {
		a[i] = h.Addr
		if h.Lost {
			a[i] = "*"
		}
	}
	return strings.Join(a, ">")
}

// Trace runs one trace from srcPort: it stops at the destination, after maxHops, or when
// three hops in a row are silent past the first answer (a filtered tail, not a long path).
func Trace(ctx context.Context, p Prober, hops int, srcPort uint16) Path {
	out := Path{SrcPort: srcPort}
	hops = min(max(hops, 1), maxHops)
	silent := 0
	for ttl := 1; ttl <= hops && ctx.Err() == nil; ttl++ {
		r := p.Probe(ctx, ttl, srcPort)
		h := Hop{TTL: ttl, Lost: !r.Addr.IsValid()}
		if !h.Lost {
			h.Addr, h.RTTMS = r.Addr.String(), float64(r.RTT)/float64(time.Millisecond)
			silent = 0
		} else if silent++; silent >= 3 {
			out.Hops = append(out.Hops, h)
			break
		}
		out.Hops = append(out.Hops, h)
		if r.Reached {
			out.Reached = true
			break
		}
	}
	return out
}

// Multipath traces from n consecutive source ports starting at base and returns one path per
// distinct route, the first seen of each. The traces run one at a time: a trace is slow, not
// heavy, and parallel probes would match each other's replies.
func Multipath(ctx context.Context, p Prober, hops, n int, base uint16) []Path {
	n = min(max(n, 1), MaxPaths)
	seen := map[string]bool{}
	var out []Path
	for i := range n {
		t := Trace(ctx, p, hops, base+uint16(i))
		if s := t.Signature(); !seen[s] {
			seen[s] = true
			out = append(out, t)
		}
	}
	return out
}

// Change is a route that is not the one seen last time.
type Change struct{ Previous, Current []string }

// Detector remembers the route signatures of every target and reports when the set changes.
type Detector struct {
	mu   sync.Mutex
	last map[string][]string
}

// Observe records paths for target. The first observation is never a change.
func (d *Detector) Observe(target string, paths []Path) (Change, bool) {
	sigs := make([]string, len(paths))
	for i, p := range paths {
		sigs[i] = p.Signature()
	}
	sort.Strings(sigs)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		d.last = map[string][]string{}
	}
	prev, had := d.last[target]
	d.last[target] = sigs
	if !had || strings.Join(prev, "|") == strings.Join(sigs, "|") {
		return Change{}, false
	}
	return Change{prev, sigs}, true
}

// Culprit is where a failed connection most likely died.
type Culprit struct {
	TTL  int    `json:"ttl"`
	Addr string `json:"addr,omitempty"` // the last router that answered
	Why  string `json:"why"`
}

// Blame names the network hop behind a failed journey step: the last router that answered
// before the path went silent. It returns false when the path reached its destination, in which
// case the fault is not the network.
func Blame(p Path) (Culprit, bool) {
	if p.Reached {
		return Culprit{}, false
	}
	var last Hop
	for _, h := range p.Hops {
		if !h.Lost {
			last = h
		}
	}
	if last.Addr == "" {
		return Culprit{TTL: 1, Why: "no router answered; the first hop is unreachable or filters probes"}, true
	}
	return Culprit{TTL: last.TTL, Addr: last.Addr, Why: "path stops after this hop"}, true
}
