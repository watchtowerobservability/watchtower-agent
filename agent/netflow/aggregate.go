package netflow

import (
	"cmp"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Aggregation bounds.
const (
	// MaxConversations is how many 5-tuples per exporter and minute are kept; the rest is summed
	// into one `other` row, so bytes are conserved.
	MaxConversations = 1_000
	// maxTuples bounds the distinct tuples held per exporter and minute while it is open; past it
	// new tuples are folded into `other` at once.
	maxTuples = 100_000
	// MaxAggExporters bounds the exporters held per open minute; past it the least recently
	// seen one is evicted (and counted), so spoofed sources cannot grow memory without limit.
	MaxAggExporters = 1_024
)

// Key is one conversation of an exporter.
type Key struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	InIf, OutIf      uint32
}

// Counts are the totals of a conversation.
type Counts struct{ Bytes, Packets uint64 }

// Row is one aggregated conversation; the `other` row has the zero Key.
type Row struct {
	Key
	Counts
}

// TopN returns the n conversations with the most bytes (ties by key, so the result is
// deterministic) and the sum of all the others (hasOther is false when nothing is left over).
func TopN(m map[Key]Counts, n int) (top []Row, other Counts, hasOther bool) {
	rows := make([]Row, 0, len(m))
	for k, c := range m {
		rows = append(rows, Row{k, c})
	}
	slices.SortFunc(rows, func(a, b Row) int {
		if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
			return c
		}
		return a.Key.compare(b.Key)
	})
	if len(rows) > n {
		for _, r := range rows[n:] {
			other.Bytes += r.Bytes
			other.Packets += r.Packets
		}
		rows, hasOther = rows[:n], true
	}
	return rows, other, hasOther
}

// compare orders keys field by field, without allocating.
func (k Key) compare(o Key) int {
	return cmp.Or(k.Src.Compare(o.Src), k.Dst.Compare(o.Dst), cmp.Compare(k.SrcPort, o.SrcPort),
		cmp.Compare(k.DstPort, o.DstPort), cmp.Compare(k.Proto, o.Proto),
		cmp.Compare(k.InIf, o.InIf), cmp.Compare(k.OutIf, o.OutIf))
}

type bucket struct {
	seen   uint64 // last touch, for eviction
	tuples map[Key]Counts
	other  Counts
	hasOth bool
}

// Aggregator sums flows per exporter and minute.
type Aggregator struct {
	mu      sync.Mutex
	open    map[time.Time]map[string]*bucket
	seq     uint64
	evicted uint64
	// Enricher, when set before the first Add, enriches every row on flush.
	Enricher *Enricher
}

// Evicted counts the exporters dropped (with their minute's data) to stay within MaxAggExporters.
func (a *Aggregator) Evicted() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.evicted
}

// NewAggregator returns an empty aggregator.
func NewAggregator() *Aggregator { return &Aggregator{open: map[time.Time]map[string]*bucket{}} }

// Add counts f in the minute of at.
func (a *Aggregator) Add(f Flow, at time.Time) {
	minute := at.UTC().Truncate(time.Minute)
	a.mu.Lock()
	defer a.mu.Unlock()
	exps := a.open[minute]
	if exps == nil {
		exps = map[string]*bucket{}
		a.open[minute] = exps
	}
	b := exps[f.Exporter]
	if b == nil {
		if len(exps) >= MaxAggExporters {
			oldest, first := "", true
			for e, o := range exps {
				if first || o.seen < exps[oldest].seen {
					oldest, first = e, false
				}
			}
			delete(exps, oldest)
			a.evicted++
		}
		b = &bucket{tuples: map[Key]Counts{}}
		exps[f.Exporter] = b
	}
	a.seq++
	b.seen = a.seq
	k := Key{f.Src, f.Dst, f.SrcPort, f.DstPort, f.Proto, f.InIf, f.OutIf}
	c, seen := b.tuples[k]
	if !seen && len(b.tuples) >= maxTuples {
		b.other.Bytes += f.Bytes
		b.other.Packets += f.Packets
		b.hasOth = true
		return
	}
	b.tuples[k] = Counts{c.Bytes + f.Bytes, c.Packets + f.Packets}
}

// Flush sends the minutes that ended before now (all of them when final is set) to out as
// `network.flow` log records and forgets them.
func (a *Aggregator) Flush(now time.Time, final bool, out sink.Sink) {
	cur := now.UTC().Truncate(time.Minute)
	a.mu.Lock()
	var done []time.Time
	for m := range a.open {
		if final || m.Before(cur) {
			done = append(done, m)
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].Before(done[j]) })
	ready := make([]map[string]*bucket, len(done))
	for i, m := range done {
		ready[i] = a.open[m]
		delete(a.open, m)
	}
	a.mu.Unlock()
	for i, m := range done {
		exps := make([]string, 0, len(ready[i]))
		for e := range ready[i] {
			exps = append(exps, e)
		}
		sort.Strings(exps)
		for _, e := range exps {
			emit(out, a.Enricher, e, m, ready[i][e])
		}
	}
}

func emit(out sink.Sink, enr *Enricher, exporter string, minute time.Time, b *bucket) {
	top, other, has := TopN(b.tuples, MaxConversations)
	if b.hasOth {
		other.Bytes += b.other.Bytes
		other.Packets += b.other.Packets
		has = true
	}
	for _, r := range top {
		attrs := rowAttrs(exporter, r, false)
		enr.Apply(attrs, exporter, r)
		out.Log("INFO", "flow", attrs, minute)
	}
	if has {
		out.Log("INFO", "flow", rowAttrs(exporter, Row{Counts: other}, true), minute)
	}
}

// rowAttrs is the wire form the worker reads (services/worker/src/flows.rs). The `other` row has
// the unspecified address on both sides.
func rowAttrs(exporter string, r Row, other bool) map[string]string {
	src, dst := "::", "::"
	if !other {
		src, dst = r.Src.String(), r.Dst.String()
	}
	return map[string]string{
		"event.name":    "network.flow",
		"flow.exporter": exporter,
		"flow.src_ip":   src,
		"flow.dst_ip":   dst,
		"flow.src_port": strconv.Itoa(int(r.SrcPort)),
		"flow.dst_port": strconv.Itoa(int(r.DstPort)),
		"flow.proto":    strconv.Itoa(int(r.Proto)),
		"flow.in_if":    strconv.FormatUint(uint64(r.InIf), 10),
		"flow.out_if":   strconv.FormatUint(uint64(r.OutIf), 10),
		"flow.bytes":    strconv.FormatUint(r.Bytes, 10),
		"flow.packets":  strconv.FormatUint(r.Packets, 10),
	}
}
