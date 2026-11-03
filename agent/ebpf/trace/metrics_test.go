package trace

import (
	"testing"
	"time"
)

func TestGenAIAndMCPHistograms(t *testing.T) {
	type pt struct {
		counts     []uint64
		sum        float64
		count      uint64
		boundsSize int
	}
	got := map[string]pt{}
	c := NewCollector(1, func(uint32) string { return "s" }, nil)
	c.Metric = func(n, _ string, b []float64, counts []uint64, sum float64, count uint64, a map[string]string, _ time.Time) {
		got[n+"/"+a["gen_ai.token.type"]] = pt{counts, sum, count, len(b)}
	}
	start := time.Unix(100, 0)
	gen := Span{Client: true, Start: start, End: start.Add(2 * time.Second), Attrs: map[string]any{
		"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai", "gen_ai.usage.input_tokens": int64(10), "gen_ai.usage.output_tokens": int64(5)}}
	c.observe(gen)
	c.observe(gen)
	c.observe(Span{Client: true, Start: start, End: start.Add(time.Second), Attrs: map[string]any{"mcp.method.name": "tools/call"}})
	c.flushMetrics(start)
	in := got["gen_ai.client.token.usage/input"]
	if in.count != 2 || in.sum != 20 || in.counts[2] != 2 || len(in.counts) != in.boundsSize+1 { // 10 is in (4, 16]
		t.Fatal(in)
	}
	d := got["gen_ai.client.operation.duration/"]
	if d.count != 2 || d.sum != 4 || d.counts[8] != 2 { // 2 s is in (1.28, 2.56]
		t.Fatal(d)
	}
	if m := got["mcp.client.operation.duration/"]; m.count != 1 || m.counts[6] != 1 { // 1 s is in (0.5, 1]
		t.Fatal(m)
	}
	for i := range maxMetricSeries + 10 {
		c.record("m", "", tokenBounds, 1, map[string]string{"k": string(rune(i + 100))})
	}
	if len(c.hists) != maxMetricSeries {
		t.Fatal(len(c.hists))
	}
}
