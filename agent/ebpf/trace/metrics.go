package trace

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"
)

// Metric writes one cumulative explicit-bucket histogram point (CFT-E07: GenAI and MCP client
// metrics from classified spans). counts has len(bounds)+1 entries.
type Metric func(name, unit string, bounds []float64, counts []uint64, sum float64, count uint64, attrs map[string]string, at time.Time)

// maxMetricSeries bounds what model names and tool methods seen on the wire can create.
const maxMetricSeries = 256

// Bucket boundaries advised by the GenAI and MCP semantic conventions.
var (
	tokenBounds    = []float64{1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864}
	genAIDurBounds = []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92}
	mcpDurBounds   = []float64{0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300}
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

// observe is called with c.mu held.
func (c *Collector) observe(s Span) {
	if c.Metric == nil {
		return
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
