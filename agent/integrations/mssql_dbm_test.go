package integrations

import (
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestMSSQLQueryStatsDeltas(t *testing.T) {
	row := func(calls, ms, lr string) []map[string]string {
		return []map[string]string{{"qhash": "0x1A2B3C4D5E6F7081", "db": "sales", "q": "SELECT * FROM orders WHERE id = 42",
			"calls": calls, "total_ms": ms, "rows_n": calls, "lreads": lr, "preads": "0"}}
	}
	var d dbm.Deltas
	var r sink.Recorder
	EmitMSSQLQueryStats(&r, &d, row("100", "1000.0", "5000"), time.Now())
	EmitMSSQLQueryStats(&r, &d, row("110", "1200.0", "5600"), time.Now())
	if v, _ := value(&r, "mssql.query.logical_reads"); v != 600 {
		t.Fatalf("logical reads = %v", v)
	}
	if v, _ := value(&r, "mssql.query.mean_time"); v != 20 {
		t.Fatalf("mean = %v", v)
	}
	if q := r.Samples[0].Attrs["query"]; strings.Contains(q, "42") {
		t.Fatalf("literal kept: %q", q)
	}
	// Plan evicted and recompiled: counters restart lower; the running total keeps growing.
	EmitMSSQLQueryStats(&r, &d, row("5", "50.0", "100"), time.Now())
	var last float64
	for _, s := range r.Samples {
		if s.Name == "mssql.query.calls" {
			last = s.Value
		}
	}
	if last != 15 {
		t.Fatalf("running total after eviction = %v", last)
	}
}

func TestMSSQLWaitCategories(t *testing.T) {
	act := MSSQLActivity([]map[string]string{
		{"db": "sales", "state": "suspended", "wait": "LCK_M_X", "qhash": "0x01", "q": "UPDATE t SET a = 1", "ms": "1500"},
		{"db": "sales", "state": "running", "wait": "", "qhash": "0x02", "q": "SELECT 1", "ms": "3"},
		{"db": "sales", "state": "suspended", "wait": "PAGEIOLATCH_SH", "qhash": "0x03", "q": "SELECT 2", "ms": "9"},
	})
	if act[0].WaitType != "Lock" || act[1].WaitType != "" || act[2].WaitType != "Buffer IO" || act[0].DurationMs != 1500 {
		t.Fatalf("%+v", act)
	}
}

// A trimmed showplan as SQL Server returns it for an ad hoc query with a sniffed parameter.
const showplanFixture = `<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan" Version="1.564">` +
	`<BatchSequence><Batch><Statements><StmtSimple StatementText="SELECT * FROM dbo.customers WHERE email = 'eve@example.com'" ` +
	`StatementSubTreeCost="0.0032831" StatementEstRows="1"><QueryPlan><RelOp NodeId="0" PhysicalOp="Index Seek" EstimateRows="1">` +
	`<Predicate><ScalarOperator ScalarString="[shop].[dbo].[customers].[email]=N&apos;eve@example.com&apos;">` +
	`<Const ConstValue="N'eve@example.com'"/></ScalarOperator></Predicate></RelOp>` +
	`<ParameterList><ColumnReference Column="@1" ParameterCompiledValue="(4711)"/></ParameterList>` +
	`</QueryPlan></StmtSimple></Statements></Batch></BatchSequence></ShowPlanXML>`

func TestScrubShowplanKeepsCostsDropsLiterals(t *testing.T) {
	got := ScrubShowplan(showplanFixture)
	if strings.Contains(got, "eve@") || strings.Contains(got, "4711") {
		t.Fatalf("literal kept: %s", got)
	}
	if !strings.Contains(got, `StatementSubTreeCost="0.0032831"`) || !strings.Contains(got, `EstimateRows="1"`) ||
		!strings.Contains(got, `[shop].[dbo].[customers].[email]=N?`) {
		t.Fatalf("damaged: %s", got)
	}
	var r sink.Recorder
	EmitPlan(&r, "mssql", "0x01", "SELECT 1", got, time.Now())
	if r.Samples[0].Attrs["db.plan.total_cost"] != "0.0032831" {
		t.Fatalf("cost %v", r.Samples[0].Attrs)
	}
}

func TestMSSQLQueryStoreAndBlocking(t *testing.T) {
	var r sink.Recorder
	EmitMSSQLQueryStore(&r, []map[string]string{{"state": "READ_ONLY", "used": "950", "max": "1000"}}, time.Now())
	EmitMSSQLRegressions(&r, []map[string]string{{"qhash": "0x01", "plans": "3", "worst_ms": "400", "best_ms": "20"}}, time.Now())
	if v, _ := value(&r, "mssql.query_store.storage_utilization"); v != 0.95 {
		t.Fatalf("storage %v", v)
	}
	if v, _ := value(&r, "mssql.query_store.regression_ratio"); v != 20 {
		t.Fatalf("ratio %v", v)
	}
	var b sink.Recorder
	reportBlocking(&b, "mssql", []map[string]string{{"waiting_pid": "55", "blocking_pid": "51", "wait_age_secs": "1200",
		"wq": "UPDATE t SET a = 'x' WHERE id = 1", "bq": "BEGIN TRAN; UPDATE t SET a = 2"}}, 1, time.Now())
	if v, _ := value(&b, "db.blocking.chain_depth"); v != 1 {
		t.Fatalf("depth %v", v)
	}
	for _, s := range b.Samples {
		if strings.Contains(s.Body, "'x'") {
			t.Fatalf("literal in chain: %s", s.Body)
		}
	}
}
