package integrations

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// jqValues indexes recorded points by name|queue|state.
func jqValues(r *sink.Recorder) map[string]float64 {
	out := map[string]float64{}
	for _, s := range r.Snapshot() {
		out[s.Name+"|"+s.Attrs["queue"]+"|"+s.Attrs["state"]] = s.Value
	}
	return out
}

func TestJobQueueEmitRoutesRowsAndZeroFills(t *testing.T) {
	seen := map[string]map[string]string{}
	r := &sink.Recorder{}
	e := &jqEmit{out: r, fw: "oban", now: time.Now(), seen: seen, got: map[string]bool{}}
	e.row("mail", "waiting", 12, 40)
	e.row("mail", "dead", 2, 999) // the age of a non-waiting row is ignored
	e.row("mail", "stalled", 1, 0)
	e.row("*", "workers", 3, 0)
	e.row("*", "processed", 50, 0)
	e.finish()
	v := jqValues(r)
	for k, want := range map[string]float64{
		"job_queue_jobs|mail|waiting": 12, "job_queue_jobs|mail|dead": 2,
		"job_queue_oldest_waiting_age_seconds|mail|": 40, "job_queue_stalled_jobs|mail|": 1,
		"job_queue_workers|*|": 3, "job_queue_processed_total|*|": 50,
	} {
		if got, ok := v[k]; !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", k, got, ok, want)
		}
	}
	if _, ok := v["job_queue_oldest_waiting_age_seconds|mail|dead"]; ok {
		t.Error("age written for a dead row")
	}
	if r.Snapshot()[0].Attrs["framework"] != "oban" {
		t.Error("framework label missing")
	}

	// Next round the queue drained: every series it had reads 0 instead of going stale.
	r2 := &sink.Recorder{}
	e = &jqEmit{out: r2, fw: "oban", now: time.Now(), seen: seen, got: map[string]bool{}}
	e.row("mail", "dead", 2, 0)
	e.finish()
	v = jqValues(r2)
	if v["job_queue_jobs|mail|waiting"] != 0 || v["job_queue_jobs|mail|dead"] != 2 {
		t.Fatalf("zero fill: %v", v)
	}
	if _, ok := v["job_queue_oldest_waiting_age_seconds|mail|"]; !ok {
		t.Fatal("age not zero-filled")
	}
	if _, ok := v["job_queue_processed_total|*|"]; ok {
		t.Fatal("counters must not be zero-filled")
	}
}

func TestJobQueueEmitCapsQueues(t *testing.T) {
	r := &sink.Recorder{}
	e := &jqEmit{out: r, fw: "rq", now: time.Now(), seen: map[string]map[string]string{}, got: map[string]bool{}}
	for i := 0; i < maxJobQueues+5; i++ {
		e.jobs(strings.Repeat("q", i+1), "waiting", 1)
	}
	if len(e.seen) != maxJobQueues || len(r.Snapshot()) != maxJobQueues {
		t.Fatalf("queues %d points %d", len(e.seen), len(r.Snapshot()))
	}
}

func TestJobQueueConfigCheck(t *testing.T) {
	for _, fw := range JobFrameworks() {
		if err := ValidateConfig(fw, json.RawMessage(`{}`)); err == nil {
			t.Errorf("%s: empty config accepted", fw)
		}
	}
	c := &JobQueueConfig{framework: "pgboss"}
	if err := load(json.RawMessage(`{"dsn":"postgres://x@h/db","queues":["a"]}`), c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != "pgboss" || c.stall != time.Hour || !c.want("a") || c.want("b") {
		t.Fatalf("defaults: %+v", c)
	}
	for _, bad := range []string{
		`{"dsn":"postgres://x@h/db","stall_after":"5s"}`,
		`{"dsn":"postgres://x@h/db","queues":["a b"]}`,
		`{"dsn":"postgres://x@h/db","typo":1}`,
	} {
		if err := load(json.RawMessage(bad), &JobQueueConfig{framework: "pgboss"}); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if got := (&JobQueueConfig{Queues: []string{"b"}}).queues([]string{"c", "b", "a"}); len(got) != 1 || got[0] != "b" {
		t.Fatalf("filter: %v", got)
	}
	if got := (&JobQueueConfig{Queues: []string{"x"}}).queues(nil); len(got) != 1 || got[0] != "x" {
		t.Fatalf("configured list: %v", got)
	}
}

func TestJobQueueSQLPlaceholdersAreEscaped(t *testing.T) {
	c := &JobQueueConfig{framework: "pgboss", Schema: `we"ird`, stall: 90 * time.Second}
	if got := jqSQL(c).Replace("{schema}.job {stall}"); got != `"we""ird".job 90` {
		t.Fatalf("pg: %s", got)
	}
	c = &JobQueueConfig{framework: "hangfire", Schema: "Hang]fire", stall: time.Hour}
	if got := jqSQL(c).Replace("{schema}.Job"); got != "[Hang]]fire].Job" {
		t.Fatalf("mssql: %s", got)
	}
}
