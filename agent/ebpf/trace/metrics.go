package trace

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Metric writes one cumulative explicit-bucket histogram point (CFT-E07: GenAI and MCP client
// metrics from classified spans). counts has len(bounds)+1 entries.
type Metric func(name, unit string, bounds []float64, counts []uint64, sum float64, count uint64, attrs map[string]string, at time.Time)

// maxMetricSeries bounds what model names, tool methods and RED routes seen on the wire can
// create (across all histograms of one collector).
const maxMetricSeries = 1024

// Bucket boundaries advised by the GenAI and MCP semantic conventions; redDurBounds is the HTTP
// server duration histogram recommended by the OTel HTTP semconv.
var (
	tokenBounds    = []float64{1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864}
	genAIDurBounds = []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92}
	mcpDurBounds   = []float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300}
	redDurBounds   = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}
)

type metricHist struct {
	name, unit string
	attrs      map[string]string
	bounds     []float64
	counts     []uint64
	sum        float64
	count      uint64
}

func strAttrs(s Span, keys ...string) map[string]string {
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := s.Attrs[k].(string); ok && v != "" {
			out[k] = v
		}
	}
	return out
}

// record adds one observation; called with c.mu held.
func (c *Collector) record(name, unit string, bounds []float64, v float64, attrs map[string]string) {
	keys := make([]string, 0, len(attrs))
	for k, a := range attrs {
		keys = append(keys, k+"="+a)
	}
	id := name + "|" + strings.Join(slices.Sorted(slices.Values(keys)), ",")
	m := c.hists[id]
	if m == nil {
		if c.hists == nil {
			c.hists = map[string]*metricHist{}
		}
		if len(c.hists) >= maxMetricSeries {
			return
		}
		m = &metricHist{name: name, unit: unit, attrs: attrs, bounds: bounds, counts: make([]uint64, len(bounds)+1)}
		c.hists[id] = m
	}
	m.counts[sort.SearchFloat64s(bounds, v)]++ // bucket i holds (bounds[i-1], bounds[i]]
	m.sum += v
	m.count++
}

// observe is called with c.mu held. svc is the resolved service.name of the span's process.
func (c *Collector) observe(svc string, s Span) {
	if c.Metric == nil {
		return
	}
	if c.RED && !s.Client {
		c.recordRED(svc, s)
	}
	if _, ok := s.Attrs["gen_ai.operation.name"]; ok {
		base := strAttrs(s, "gen_ai.provider.name", "gen_ai.operation.name", "gen_ai.request.model")
		for key, typ := range map[string]string{"gen_ai.usage.input_tokens": "input", "gen_ai.usage.output_tokens": "output"} {
			if n, ok := tokenCount(s.Attrs[key]); ok {
				a := maps.Clone(base)
				a["gen_ai.token.type"] = typ
				c.record("gen_ai.client.token.usage", "{token}", tokenBounds, n, a)
			}
		}
		c.record("gen_ai.client.operation.duration", "s", genAIDurBounds, s.End.Sub(s.Start).Seconds(), base)
	}
	if _, ok := s.Attrs["mcp.method.name"]; ok {
		name := "mcp.server.operation.duration"
		if s.Client {
			name = "mcp.client.operation.duration"
		}
		c.record(name, "s", mcpDurBounds, s.End.Sub(s.Start).Seconds(), strAttrs(s, "mcp.method.name", "gen_ai.tool.name"))
	}
}

// recordRED emits the RED server duration histogram for one SERVER span (USM metrics mode, D11):
// rpc.server.duration for gRPC/RPC, http.server.request.duration otherwise, keyed by the low
// cardinality dimensions the /apm red query reads. It needs no SDK and stores no spans.
func (c *Collector) recordRED(svc string, s Span) {
	dur := s.End.Sub(s.Start).Seconds()
	if _, ok := s.Attrs["rpc.system"]; ok {
		a := redAttrs(s, svc, "rpc.system", "rpc.service", "rpc.method", "rpc.grpc.status_code", "server.port")
		c.record("rpc.server.duration", "s", redDurBounds, dur, a)
		return
	}
	if _, ok := s.Attrs["http.request.method"]; ok {
		a := redAttrs(s, svc, "http.request.method", "http.response.status_code", "server.port")
		if p, ok := s.Attrs["url.path"].(string); ok && p != "" {
			a["http.route"] = templateRoute(p)
		}
		c.record("http.server.request.duration", "s", redDurBounds, dur, a)
	}
}

// redAttrs builds the metric label set: service.name plus the named span attributes that are set.
func redAttrs(s Span, svc string, keys ...string) map[string]string {
	a := map[string]string{"service.name": svc}
	for _, k := range keys {
		switch v := s.Attrs[k].(type) {
		case string:
			if v != "" {
				a[k] = v
			}
		case int64:
			a[k] = strconv.FormatInt(v, 10)
		}
	}
	return a
}

// templateRoute collapses high-cardinality path segments (numeric ids, UUIDs, long hex) to {id} so
// the http.route label stays bounded without the application's router. shortcut: a heuristic, so a
// non-id numeric/hex segment is templated too; upgrade with router-reported routes when available.
func templateRoute(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if idSegment(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

func idSegment(s string) bool {
	if s == "" {
		return false
	}
	digits, hex := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			hex++
		case (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-':
			hex++
		}
	}
	return digits == len(s) || // all digits (12, 00042)
		(hex == len(s) && digits > 0 && len(s) >= 8) // uuid or long hex id (no all-letter words)
}

func tokenCount(v any) (float64, bool) {
	var n float64
	switch t := v.(type) {
	case int64:
		n = float64(t)
	case string:
		if _, err := fmt.Sscan(t, &n); err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return n, n >= 0
}

func (c *Collector) flushMetrics(at time.Time) {
	if c.Metric == nil {
		return
	}
	c.mu.Lock()
	out := make([]metricHist, 0, len(c.hists))
	for _, m := range c.hists {
		cp := *m
		cp.counts = slices.Clone(m.counts)
		out = append(out, cp)
	}
	c.mu.Unlock()
	for _, m := range out {
		c.Metric(m.name, m.unit, m.bounds, m.counts, m.sum, m.count, m.attrs, at)
	}
}
