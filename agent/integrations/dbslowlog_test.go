package integrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/logs"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// tailFixture appends fixture to a followed file and returns what the slow-log sink emitted.
func tailFixture(t *testing.T, engine, fixture string) []sink.Sample {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "slow.log")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	start := `^# Time: `
	if engine == "postgresql" {
		start = `^\S`
	}
	var r sink.Recorder
	tl, err := logs.NewTailer([]logs.TailSpec{{Path: p, MultilineStart: start}}, logs.MemState(), slowLogSink{out: &r, engine: engine})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tl.Poll(now)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	tl.Poll(now.Add(time.Second))
	tl.Poll(now.Add(10 * time.Second)) // the last record is flushed after a quiet period
	return r.Snapshot()
}

func TestMySQLSlowLogFixture(t *testing.T) {
	got := tailFixture(t, "mysql", "testdata/mysql-slow.log")
	if len(got) != 2 {
		t.Fatalf("want 2 statements (header and Quit dropped): %+v", got)
	}
	a := got[0].Attrs
	if a["event.name"] != "db.query.sample" || a["db.namespace"] != "shop" || a["db.sample.source"] != "slow_log" ||
		a["db.query.text"] != "SELECT * FROM orders WHERE customer_email = ? AND total > ?;" {
		t.Fatalf("%v", a)
	}
	if a["db.query.hash"] != dbm.QueryHash("SELECT * FROM orders WHERE customer_email = 'bob@example.com' AND total > 250;", false) {
		t.Fatalf("hash %v", a["db.query.hash"])
	}
	if !strings.Contains(got[0].Body, `"duration_ms":2000.18`) || !strings.Contains(got[0].Body, `"rows_examined":1000000`) ||
		!strings.Contains(got[0].Body, `"user":"app"`) {
		t.Fatalf("%s", got[0].Body)
	}
	if got[1].Attrs["db.namespace"] != "analytics" || strings.Contains(got[1].Attrs["db.query.text"], "2026") {
		t.Fatalf("mariadb schema / literal: %v", got[1].Attrs)
	}
	for _, s := range got {
		if strings.Contains(s.Body+s.Attrs["db.query.text"], "bob@") || strings.Contains(s.Body, "10.0.0.7") {
			t.Fatalf("leak: %+v", s)
		}
	}
}

func TestPGSlowLogFixture(t *testing.T) {
	got := tailFixture(t, "postgresql", "testdata/pg-slow.log")
	if len(got) != 3 {
		t.Fatalf("want sample+plan+sample: %+v", got)
	}
	if a := got[0].Attrs; a["db.sample.source"] != "auto_explain" || a["db.namespace"] != "shop" ||
		a["db.query.text"] != "SELECT * FROM orders WHERE customer_email = ?" {
		t.Fatalf("%v", a)
	}
	if a := got[1].Attrs; a["event.name"] != "db.query.plan" || a["db.plan.node_type"] != "Seq Scan" || a["db.plan.total_cost"] != "18334" {
		t.Fatalf("plan attrs %v", a)
	}
	if a := got[2].Attrs; a["db.sample.source"] != "duration_log" || a["db.query.text"] != "UPDATE orders SET status = $1 WHERE id = ?" {
		t.Fatalf("%v", a)
	}
	for _, s := range got {
		if strings.Contains(s.Body+s.Attrs["db.query.text"], "bob@") || strings.Contains(s.Body, "shipped") {
			t.Fatalf("leak: %+v", s)
		}
	}
}

func TestSlowLogConfigCheck(t *testing.T) {
	if (&SlowLogConfig{Engine: "mysql", Path: "/var/log/mysql/slow.log"}).check() != nil {
		t.Fatal("valid config refused")
	}
	if (&SlowLogConfig{Engine: "oracle", Path: "x"}).check() == nil || (&SlowLogConfig{Engine: "mysql"}).check() == nil {
		t.Fatal("bad config accepted")
	}
}
