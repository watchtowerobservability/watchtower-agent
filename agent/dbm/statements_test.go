package dbm

import (
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestDeltasBaselineResetAndEviction(t *testing.T) {
	var d Deltas
	st := func(calls int64, ms float64) Statement {
		return Statement{Key: "db/1", QueryID: "1", Calls: calls, TotalMs: ms, Rows: calls}
	}
	if out := d.Observe([]Statement{st(10, 100)}, 10); len(out) != 0 {
		t.Fatalf("first sight must only set the baseline: %+v", out)
	}
	out := d.Observe([]Statement{st(14, 140)}, 10)
	if len(out) != 1 || out[0].Calls != 4 || out[0].MeanMs != 10 || out[0].Delta.Calls != 4 {
		t.Fatalf("delta: %+v", out)
	}
	if out := d.Observe([]Statement{st(14, 140)}, 10); len(out) != 0 {
		t.Fatalf("idle statement reported: %+v", out)
	}
	// pg_stat_statements_reset(): the current value is the delta, the running total keeps going.
	out = d.Observe([]Statement{st(3, 60)}, 10)
	if len(out) != 1 || out[0].Calls != 7 || out[0].MeanMs != 20 {
		t.Fatalf("after reset: %+v", out)
	}
	d.Observe(nil, 10)
	if len(d.acc) != 0 {
		t.Fatalf("evicted statement kept: %+v", d.acc)
	}
}

func TestDeltasLimitKeepsBusiest(t *testing.T) {
	var d Deltas
	rows := func(n int64) []Statement {
		return []Statement{{Key: "a", Calls: n, TotalMs: float64(n)}, {Key: "b", Calls: n, TotalMs: float64(10 * n)}}
	}
	d.Observe(rows(1), 1)
	if out := d.Observe(rows(2), 1); len(out) != 1 || out[0].Key != "b" {
		t.Fatalf("%+v", out)
	}
}

func TestObfuscatePlanDropsLiterals(t *testing.T) {
	p := ObfuscatePlan(`[{"Plan":{"Node Type":"Index Scan","Total Cost":8.3,"Index Cond":"(email = 'bob@x.io'::text)","Filter":"(age > 42)"}}]`)
	if p == "" || strings.Contains(p, "bob@") || strings.Contains(p, "42") || !strings.Contains(p, "8.3") || !strings.Contains(p, "Index Scan") {
		t.Fatalf("plan: %s", p)
	}
	if ObfuscatePlan("not json") != "" {
		t.Fatal("non-JSON plan kept")
	}
}

func TestSamplerGroupsAndFlushes(t *testing.T) {
	var s Sampler
	q := "SELECT * FROM users WHERE email = 'bob@x.io'"
	for i := 0; i < 4; i++ {
		s.Add([]Activity{{Database: "app", State: "active", WaitType: "IO", Wait: "DataFileRead", QueryID: "9", Query: q, DurationMs: float64(i)}})
	}
	s.Add(nil)
	var r sink.Recorder
	c := s.Flush(&r, "postgresql", time.Now())
	if len(c) != 1 || c[0].Raw != q || strings.Contains(c[0].Query, "bob@") {
		t.Fatalf("candidates %+v", c)
	}
	var load float64
	for _, x := range r.Samples {
		if strings.Contains(x.Body, "bob@") || strings.Contains(x.Attrs["db.query.text"], "bob@") {
			t.Fatalf("literal leaked: %+v", x)
		}
		if x.Name == "db.activity.sessions" {
			load = x.Value
		}
	}
	if load != 0.8 || len(r.Samples) != 2 {
		t.Fatalf("load %v samples %+v", load, r.Samples)
	}
	if s.Ticks() != 0 || s.Flush(&r, "postgresql", time.Now()) != nil {
		t.Fatal("flush did not reset")
	}
}
