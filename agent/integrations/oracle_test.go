package integrations

import (
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestOracleConfigModes(t *testing.T) {
	if (&OracleConfig{ExporterConfig: ExporterConfig{URL: "http://127.0.0.1:9161/metrics"}}).check() != nil {
		t.Fatal("exporter mode refused")
	}
	if (&OracleConfig{DSN: "oracle://u:p@db:1521/ORCL"}).check() != nil {
		t.Fatal("native mode refused")
	}
	if (&OracleConfig{DSN: "u/p@db"}).check() == nil || (&OracleConfig{}).check() == nil {
		t.Fatal("bad config accepted")
	}
}

func TestOracleRoundAndSQLDeltas(t *testing.T) {
	var r sink.Recorder
	now := time.Now()
	EmitOracleRound(&r, []map[string]string{{"n": "parse count (hard)", "v": "120"}, {"n": "unrelated", "v": "1"}}, "stat", now)
	EmitOracleRound(&r, []map[string]string{{"c": "User I/O", "ms": "5000", "n": "40"}}, "wait", now)
	EmitOracleRound(&r, []map[string]string{{"ts": "USERS", "p": "91.5"}}, "tablespace", now)
	if v, _ := value(&r, "oracle.parses.hard"); v != 120 {
		t.Fatalf("hard parses %v", v)
	}
	if v, _ := value(&r, "oracle.tablespace.used_percent"); v != 91.5 {
		t.Fatalf("tablespace %v", v)
	}
	var d dbm.Deltas
	row := func(calls, ms string) []map[string]string {
		return []map[string]string{{"db": "APP", "id": "7h35uxf5uhmm1", "q": "SELECT * FROM orders WHERE id = 99",
			"calls": calls, "total_ms": ms, "rows_n": calls, "gets": "10", "reads": "0"}}
	}
	EmitOracleSQL(&r, &d, row("10", "100"), now)
	top := EmitOracleSQL(&r, &d, row("12", "130"), now)
	if len(top) != 1 || top[0].MeanMs != 15 || top[0].QueryID != "7h35uxf5uhmm1" {
		t.Fatalf("%+v", top)
	}
}

func TestOracleActivityAndPlan(t *testing.T) {
	act := OracleActivity([]map[string]string{
		{"db": "APP", "state": "ACTIVE", "wclass": "Concurrency", "wait": "enq: TX - row lock contention", "sqlid": "a1", "q": "UPDATE t SET x = 1", "ms": "4000"},
		{"db": "APP", "state": "ACTIVE", "wclass": "", "wait": "", "sqlid": "a2", "q": "SELECT 1 FROM dual", "ms": "0"},
	})
	if act[0].WaitType != "Concurrency" || act[0].State != "active" || act[1].WaitType != "" {
		t.Fatalf("%+v", act)
	}
	plan, err := OraclePlanJSON([]OraclePlanStep{
		{ID: 0, Parent: -1, Operation: "SELECT STATEMENT ", Cost: 42},
		{ID: 1, Parent: 0, Operation: "TABLE ACCESS BY INDEX ROWID", Object: "APP.ORDERS", Cost: 42, Rows: 1},
		{ID: 2, Parent: 1, Operation: "INDEX UNIQUE SCAN", Object: "APP.ORDERS_PK", Cost: 1, Rows: 1,
			Access: `"ID"=4711`, Filter: `"EMAIL"='zoe@example.com'`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "4711") || strings.Contains(plan, "zoe@") || !strings.Contains(plan, "ORDERS_PK") {
		t.Fatalf("plan %s", plan)
	}
	var r sink.Recorder
	EmitPlan(&r, "oracle", "a1", "SELECT 1", plan, time.Now())
	if a := r.Samples[0].Attrs; a["db.plan.total_cost"] != "42" || a["db.plan.node_type"] != "SELECT STATEMENT" {
		t.Fatalf("%v", a)
	}
}
