package trace

import (
	"sync"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// Stats receives the module's self metrics (cumulative counters); nil sends none.
type Stats func(name string, value float64, at time.Time)

// Sink receives finished spans for one resource (service.name of the observed process).
type Sink func(res map[string]string, spans []*tracepb.Span)

// Collector applies the event rate cap, assembles spans and hands them to the sink in batches.
type Collector struct {
	Metric  Metric // optional: GenAI and MCP client metrics, see metrics.go
	hists   map[string]*metricHist
	mu      sync.Mutex
	asm     *Assembler
	lim     *Limiter
	service func(pid uint32) string
	sink    Sink
	buf     map[string][]*tracepb.Span
	// Sel, when active, drops events of processes the selection leaves out (before the rate cap).
	Sel *Selection
	// Payload, when set, records capped and masked HTTP bodies on server spans (payload.go).
	Payload *Payload
	spans   uint64
}

// NewCollector builds a collector. service maps a pid to its service.name.
func NewCollector(maxEventsPerSec int, service func(uint32) string, sink Sink) *Collector {
	return &Collector{asm: NewAssembler(), lim: NewLimiter(maxEventsPerSec), service: service, sink: sink, buf: map[string][]*tracepb.Span{}}
}

// Feed handles one captured event.
func (c *Collector) Feed(ev Event) {
	if c.Sel.Active() && !c.Sel.Keep(ev.PID, ev.TS) {
		return
	}
	if !c.lim.Allow(ev.TS) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sp, ok := c.asm.Handle(ev)
	if !ok {
		return
	}
	svc := c.service(sp.PID)
	c.Payload.apply(&sp, svc)
	c.buf[svc] = append(c.buf[svc], sp.Proto())
	c.observe(sp)
	c.spans++
}

// Spans is the number of spans assembled so far.
func (c *Collector) Spans() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spans
}

// Flush sends what is buffered.
func (c *Collector) Flush() {
	c.mu.Lock()
	buf := c.buf
	c.buf = map[string][]*tracepb.Span{}
	c.mu.Unlock()
	for svc, spans := range buf {
		c.sink(map[string]string{"service.name": svc, "telemetry.sdk.name": "wt-ebpf"}, spans)
	}
}

// Dropped is the number of events refused by the rate cap.
func (c *Collector) Dropped() uint64 { return c.lim.Dropped() }
