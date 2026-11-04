package integrations

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestMySQLDigestDeltas(t *testing.T) {
	row := func(calls, ms, ex string) []map[string]string {
		return []map[string]string{{"db": "shop", "digest": "abc", "q": "SELECT * FROM `orders` WHERE `id` = ?",
			"calls": calls, "total_ms": ms, "rows_sent": calls, "rows_examined": ex, "no_index": "0"}}
	}
	var d dbm.Deltas
	var r sink.Recorder
	EmitMySQLDigests(&r, &d, row("10", "100.5", "1000"), time.Now())
	if len(r.Samples) != 0 {
		t.Fatalf("first read is the baseline: %+v", r.Samples)
	}
	EmitMySQLDigests(&r, &d, row("15", "150.5", "1500"), time.Now())
	if v, _ := value(&r, "mysql.query.calls"); v != 5 {
		t.Fatalf("calls = %v", v)
	}
	if v, _ := value(&r, "mysql.query.rows_examined"); v != 500 {
		t.Fatalf("rows examined = %v", v)
	}
	if v, _ := value(&r, "mysql.query.mean_time"); v != 10 {
		t.Fatalf("mean = %v", v)
	}
	if a := r.Samples[0].Attrs; a["digest"] != "abc" || a["database"] != "shop" {
		t.Fatalf("attrs %v", a)
	}
}

func TestMySQLActivityWaits(t *testing.T) {
	act := MySQLActivity([]map[string]string{
		{"db": "shop", "state": "Query", "wait": "wait/io/table/sql/handler", "digest": "d1", "q": "SELECT 1", "ms": "12.5"},
		{"db": "shop", "state": "Query", "wait": "", "digest": "d2", "q": "SELECT 2", "ms": "1"},
	})
	if act[0].WaitType != "io" || act[0].Wait != "io/table/sql/handler" || act[0].DurationMs != 12.5 {
		t.Fatalf("%+v", act[0])
	}
	if act[1].WaitType != "" || act[1].Wait != "" {
		t.Fatalf("no wait is CPU: %+v", act[1])
	}
}

func TestInnoDBDeadlockFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/mysql_innodb_status_deadlock.txt")
	if err != nil {
		t.Fatal(err)
	}
	d, ok := ParseInnoDBDeadlock(string(b))
	if !ok || d.At != "2026-11-02 10:11:12" || len(d.Transactions) != 2 || d.RolledBack != 2 {
		t.Fatalf("%+v", d)
	}
	t1 := d.Transactions[0]
	if t1.Table != "`bank`.`accounts`" || t1.Index != "PRIMARY" || t1.WaitsFor != "X locks rec but not gap" ||
		t1.Holds != "X locks rec but not gap" || !strings.HasPrefix(t1.Query, "UPDATE accounts SET balance") {
		t.Fatalf("%+v", t1)
	}
	body, _ := json.Marshal(d)
	for _, leak := range []string{"alice", "100", "hex", "rent"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("deadlock record leaks %q: %s", leak, body)
		}
	}
	if _, ok := ParseInnoDBDeadlock("no deadlock here"); ok {
		t.Fatal("no section must be false")
	}
}

func TestGTIDBehind(t *testing.T) {
	if n := gtidBehind("3E11FA47-71CA-11E1-9E33-C80AA9429562:1-100,\n4a:1-5", "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-90:95"); n != 14 {
		t.Fatalf("behind = %d", n)
	}
	if n := gtidBehind("u:1-10:tag:1-4", "u:1-10:tag:1-3"); n != 1 {
		t.Fatalf("tagged = %d", n)
	}
	if n := gtidBehind("u:1-10", "u:1-10"); n != 0 {
		t.Fatalf("caught up = %d", n)
	}
	if n := mariaGTIDBehind("0-1-120,1-2-50", "0-1-100,1-2-50"); n != 20 {
		t.Fatalf("mariadb = %d", n)
	}
	var r sink.Recorder
	EmitMySQLReplica(&r, map[string]string{"Replica_SQL_Running": "Yes", "Channel_Name": "east",
		"Retrieved_Gtid_Set": "u:1-10", "Executed_Gtid_Set": "u:1-7"}, time.Now())
	if v, _ := value(&r, "mysql.replica.gtid_behind"); v != 3 || r.Samples[0].Attrs["channel"] != "east" {
		t.Fatalf("%+v", r.Samples)
	}
}

func TestExplainGateLimits(t *testing.T) {
	var g explainGate
	now := time.Now()
	var cands []dbm.Candidate
	for _, q := range []string{"select 1", "select 2", "update t set a = 1", "select 3", "select 4", "select 5", "select 6"} {
		cands = append(cands, dbm.Candidate{Query: q, Raw: q})
	}
	if got := g.pick(cands, now); len(got) != dbExplainPerRound || got[2].Query != "select 3" {
		t.Fatalf("first pick %+v", got)
	}
	if got := g.pick(cands, now.Add(time.Minute)); len(got) != 1 || got[0].Query != "select 6" {
		t.Fatalf("second pick %+v", got)
	}
	if got := g.pick(cands, now.Add(dbExplainPerSig+2*time.Minute)); len(got) != dbExplainPerRound {
		t.Fatalf("after the window %+v", got)
	}
}

func TestHashSinkStampsRawStatementHash(t *testing.T) {
	var r sink.Recorder
	raw := "SELECT * FROM t WHERE id IN (1, 2, 3)"
	h := &hashSink{Sink: &r, raw: map[string]string{dbm.BindSafe(raw): raw}}
	h.Log("INFO", "{}", map[string]string{"db.query.text": dbm.BindSafe(raw)}, time.Now())
	h.Log("INFO", "{}", map[string]string{"db.query.text": "other"}, time.Now())
	if got := r.Samples[0].Attrs["db.query.hash"]; got != dbm.QueryHash(raw, false) || got == "" {
		t.Fatalf("hash %q", got)
	}
	if _, ok := r.Samples[1].Attrs["db.query.hash"]; ok {
		t.Fatal("unknown text must not get a hash")
	}
}
