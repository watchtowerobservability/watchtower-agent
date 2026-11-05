package trace

import (
	"strconv"
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
	c.observe("s", gen)
	c.observe("s", gen)
	c.observe("s", Span{Client: true, Start: start, End: start.Add(time.Second), Attrs: map[string]any{"mcp.method.name": "tools/call"}})
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
		c.record("m", "", tokenBounds, 1, map[string]string{"k": strconv.Itoa(i)})
	}
	if len(c.hists) != maxMetricSeries {
		t.Fatal(len(c.hists))
	}
}

func TestREDServerHistograms(t *testing.T) {
	got := map[string]metricHist{}
	c := NewCollector(1, func(uint32) string { return "s" }, nil)
	c.RED = true
	c.Metric = func(n, _ string, _ []float64, counts []uint64, sum float64, count uint64, a map[string]string, _ time.Time) {
		got[n] = metricHist{attrs: a, counts: counts, sum: sum, count: count}
	}
	start := time.Unix(100, 0)
	// A SERVER HTTP span with a numeric id in the path.
	c.observe("checkout", Span{Start: start, End: start.Add(50 * time.Millisecond), Attrs: map[string]any{
		"http.request.method": "GET", "url.path": "/users/42/cart", "http.response.status_code": int64(200), "server.port": int64(8080)}})
	// A gRPC SERVER span -> rpc.server.duration, not http.
	c.observe("checkout", Span{Start: start, End: start.Add(time.Second), Attrs: map[string]any{
		"http.request.method": "POST", "rpc.system": "grpc", "rpc.method": "Pay", "server.port": int64(9000)}})
	// A CLIENT span must not produce a server metric.
	c.observe("checkout", Span{Client: true, Start: start, End: start.Add(time.Second), Attrs: map[string]any{"http.request.method": "GET", "url.path": "/x"}})
	c.flushMetrics(start)

	h := got["http.server.request.duration"]
	if h.count != 1 || h.sum != 0.05 || h.counts[3] != 1 { // 50 ms is in (0.025, 0.05]
		t.Fatalf("http red %+v", h)
	}
	if h.attrs["http.route"] != "/users/{id}/cart" || h.attrs["service.name"] != "checkout" ||
		h.attrs["http.response.status_code"] != "200" || h.attrs["server.port"] != "8080" {
		t.Fatalf("http red attrs %v", h.attrs)
	}
	r := got["rpc.server.duration"]
	if r.count != 1 || r.attrs["rpc.method"] != "Pay" || r.attrs["service.name"] != "checkout" {
		t.Fatalf("rpc red %+v", r)
	}
	if r.attrs["http.route"] != "" { // a gRPC span is rpc.server.duration only, no http metric
		t.Fatalf("grpc span carried an http route: %v", r.attrs)
	}
	if h.count+r.count != 2 { // the CLIENT span produced neither
		t.Fatalf("client span leaked into RED: http %d rpc %d", h.count, r.count)
	}
}

func TestTemplateRoute(t *testing.T) {
	cases := [][2]string{
		{"/users/42/cart", "/users/{id}/cart"},
		{"/", "/"},
		{"/health", "/health"},
		{"/v1/orders/123e4567-e89b-12d3-a456-426614174000", "/v1/orders/{id}"},
		{"/files/deadbeefcafe1234", "/files/{id}"},
		{"/api/v2/status", "/api/v2/status"},
	}
	for _, c := range cases {
		if got := templateRoute(c[0]); got != c[1] {
			t.Errorf("%q -> %q, want %q", c[0], got, c[1])
		}
	}
}
