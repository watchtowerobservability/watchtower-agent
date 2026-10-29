package aiserving

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func scrape(t *testing.T, kind, file string) *sink.Recorder {
	t.Helper()
	b, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var r sink.Recorder
	var s Scraper
	if err := s.Map(kind, "t", b, &r, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	return &r
}

func find(t *testing.T, r *sink.Recorder, name string, want float64) sink.Sample {
	t.Helper()
	for _, s := range r.Snapshot() {
		if s.Name == name && math.Abs(s.Value-want) < 1e-9 {
			return s
		}
	}
	t.Fatalf("no %s = %v in %+v", name, want, r.Snapshot())
	return sink.Sample{}
}

func TestVLLMMetricsMapped(t *testing.T) {
	r := scrape(t, "vllm", "vllm.prom")
	s := find(t, r, "gen_ai.server.time_to_first_token", 0.5)
	if s.Attrs["gen_ai.request.model"] != "llama-3-8b" {
		t.Fatalf("attrs: %v", s.Attrs)
	}
	find(t, r, "gen_ai.server.time_per_output_token", 0.025)
	find(t, r, "gen_ai.server.request.duration", 3)
	find(t, r, "llm.queue.depth", 7)
}

func TestTritonMetricsMapped(t *testing.T) {
	r := scrape(t, "triton", "triton.prom")
	find(t, r, "gen_ai.server.request.duration", 0.002) // 4e6 us / 2000 requests
	find(t, r, "llm.queue.depth", 3)
	find(t, r, "gpu.utilization", 0.62)
	find(t, r, "gpu.memory.used", 2147483648)
	find(t, r, "gpu.power", 180.5)
}

func TestDCGMMetricsMapped(t *testing.T) {
	r := scrape(t, "dcgm", "dcgm.prom")
	s := find(t, r, "gpu.utilization", 0.85)
	if s.Attrs["gpu.index"] != "0" || s.Attrs["hw.id"] != "GPU-aaa" {
		t.Fatalf("attrs: %v", s.Attrs)
	}
	find(t, r, "gpu.utilization", 0.10)
	find(t, r, "gpu.memory.used", 1024*1024*1024)
	find(t, r, "gpu.temperature", 61)
	find(t, r, "gpu.power", 250.5)
}

func TestTGIMetricsMapped(t *testing.T) {
	r := scrape(t, "tgi", "tgi.prom")
	find(t, r, "gen_ai.server.request.duration", 3)
	find(t, r, "llm.queue.depth", 4)
}

func TestSecondScrapeUsesIntervalMean(t *testing.T) {
	var s Scraper
	var r sink.Recorder
	at := time.Unix(0, 0)
	_ = s.Map("tgi", "t", []byte("tgi_request_duration_sum 10\ntgi_request_duration_count 10\n"), &r, at)
	_ = s.Map("tgi", "t", []byte("tgi_request_duration_sum 16\ntgi_request_duration_count 12\n"), &r, at)
	find(t, &r, "gen_ai.server.request.duration", 3) // (16-10)/(12-10)
}

func TestParseEscapedLabelsAndJunk(t *testing.T) {
	got := parse(strings.NewReader("# c\nx{a=\"q\\\"z\",b=\"1\"} 2 1700000000\nbad{\nnan_m NaN\ny 3\n"))
	if len(got) != 2 || got[0].labels["a"] != `q"z` || got[0].value != 2 || got[1].name != "y" {
		t.Fatalf("parsed %+v", got)
	}
}

func TestScrapeRefusesNonLocalByDefault(t *testing.T) {
	remote := Config{Targets: []Target{{Kind: "vllm", URL: "http://10.0.0.5:8000/metrics"}}}
	if remote.Validate() == nil {
		t.Fatal("a non-local target must be refused")
	}
	remote.AllowRemote = true
	if err := remote.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://127.0.0.1:8000/metrics", "http://localhost:8002/metrics", "http://[::1]:9400/metrics"} {
		if err := (Config{Targets: []Target{{Kind: "dcgm", URL: u}}}).Validate(); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	if (Config{Targets: []Target{{Kind: "nope", URL: "http://127.0.0.1/"}}}).Validate() == nil {
		t.Fatal("unknown kind must be refused")
	}
}
