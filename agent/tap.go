package main

// Live tap (CFT-A23, Alloy live debugging): the fleet server asks for "the output of module X for
// N seconds"; every sample, log record and span that module hands the exporter is also copied,
// redacted and capped (60 s, 500 items), and returned as one OpAMP custom message. The data
// still goes to the gateway as usual; the tap only observes.

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	tapCapability = "io.watchtower.tap"
	tapMaxSeconds = 60
	tapMaxItems   = 500
	tapMaxBody    = 1024
)

type tapItem struct {
	At    int64             `json:"t"`
	Kind  string            `json:"kind"` // gauge, sum, histogram (Value is its sum), log, span
	Name  string            `json:"name,omitempty"`
	Value float64           `json:"value,omitempty"`
	Body  string            `json:"body,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

type tapSession struct {
	until   time.Time
	items   []tapItem
	dropped int
}

type taps struct {
	mu     sync.Mutex
	active map[string]*tapSession
}

func (t *taps) record(module string, it tapItem) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.active[module]
	if s == nil || time.Now().After(s.until) {
		return
	}
	if len(s.items) >= tapMaxItems {
		s.dropped++
		return
	}
	if len(it.Body) > tapMaxBody {
		it.Body = it.Body[:tapMaxBody]
	}
	s.items = append(s.items, it)
}

// Run taps module for seconds (capped) and returns the redacted result as JSON.
func (t *taps) Run(ctx context.Context, module string, seconds int) []byte {
	seconds = min(max(seconds, 1), tapMaxSeconds)
	s := &tapSession{until: time.Now().Add(time.Duration(seconds) * time.Second)}
	t.mu.Lock()
	if t.active == nil {
		t.active = map[string]*tapSession{}
	}
	t.active[module] = s
	t.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(time.Until(s.until)):
	}
	t.mu.Lock()
	delete(t.active, module)
	t.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"module": module, "seconds": seconds, "items": s.items, "dropped": s.dropped})
	return RedactTap(b)
}

var tapSecrets = []*regexp.Regexp{
	regexp.MustCompile(`\bwt[a-z]_[A-Za-z0-9]{4,}_[A-Za-z0-9_\-]{8,}`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{8,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`),
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)=[^\s&"]+`),
}

// RedactTap scrubs secret-looking values (tokens, bearer headers, passwords) from tap output.
func RedactTap(b []byte) []byte {
	for _, re := range tapSecrets {
		b = re.ReplaceAll(b, []byte("[REDACTED]"))
	}
	return b
}

func (t *taps) wrap(module string, out Exporter) Exporter { return &tapExporter{module, out, t} }

// tapExporter passes everything through and copies it while a tap of its module is active. It
// keeps the optional exporter interfaces (resource attributes, spans, delivery) of the inner one.
type tapExporter struct {
	module string
	Exporter
	t *taps
}

func (e *tapExporter) on() bool {
	e.t.mu.Lock()
	defer e.t.mu.Unlock()
	return e.t.active[e.module] != nil
}

func (e *tapExporter) Gauge(n, u string, v float64, a map[string]string, at time.Time) {
	if e.on() {
		e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "gauge", Name: n, Value: v, Attrs: a})
	}
	e.Exporter.Gauge(n, u, v, a, at)
}

func (e *tapExporter) Sum(n, u string, v float64, a map[string]string, at time.Time) {
	if e.on() {
		e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "sum", Name: n, Value: v, Attrs: a})
	}
	e.Exporter.Sum(n, u, v, a, at)
}

func (e *tapExporter) Log(sev, body string, a map[string]string, at time.Time) {
	if e.on() {
		e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "log", Name: sev, Body: body, Attrs: a})
	}
	e.Exporter.Log(sev, body, a, at)
}

func (e *tapExporter) GaugeRes(n, u string, v float64, res, a map[string]string, at time.Time) {
	if rs, ok := e.Exporter.(sink.ResourceSink); ok {
		if e.on() {
			e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "gauge", Name: n, Value: v, Attrs: a})
		}
		rs.GaugeRes(n, u, v, res, a, at)
		return
	}
	e.Gauge(n, u, v, a, at)
}

func (e *tapExporter) SumRes(n, u string, v float64, res, a map[string]string, at time.Time) {
	if rs, ok := e.Exporter.(sink.ResourceSink); ok {
		if e.on() {
			e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "sum", Name: n, Value: v, Attrs: a})
		}
		rs.SumRes(n, u, v, res, a, at)
		return
	}
	e.Sum(n, u, v, a, at)
}

func (e *tapExporter) LogRes(sev, body string, res, a map[string]string, at time.Time) {
	if rs, ok := e.Exporter.(sink.ResourceSink); ok {
		if e.on() {
			e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "log", Name: sev, Body: body, Attrs: a})
		}
		rs.LogRes(sev, body, res, a, at)
		return
	}
	e.Log(sev, body, a, at)
}

func (e *tapExporter) AddSpans(res map[string]string, spans []*tracepb.Span) {
	if e.on() {
		for _, s := range spans {
			e.t.record(e.module, tapItem{At: int64(s.GetStartTimeUnixNano() / 1e6), Kind: "span", Name: s.GetName(), Attrs: res}) //nolint:gosec // ns timestamp
		}
	}
	if sa, ok := e.Exporter.(spanAdder); ok {
		sa.AddSpans(res, spans)
	}
}

func (e *tapExporter) Histogram(n, u string, bounds []float64, counts []uint64, sum float64, count uint64, a map[string]string, at time.Time) {
	if e.on() {
		e.t.record(e.module, tapItem{At: at.UnixMilli(), Kind: "histogram", Name: n, Value: sum, Attrs: a})
	}
	if h, ok := e.Exporter.(histogrammer); ok {
		h.Histogram(n, u, bounds, counts, sum, count, a, at)
	}
}

func (e *tapExporter) Flush(ctx context.Context) error {
	if d, ok := e.Exporter.(sink.Delivering); ok {
		return d.Flush(ctx)
	}
	return nil
}

func (e *tapExporter) Buffered() int {
	if d, ok := e.Exporter.(sink.Delivering); ok {
		return d.Buffered()
	}
	return 0
}
