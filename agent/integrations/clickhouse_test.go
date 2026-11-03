package integrations

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestClickHouseQueryLogRowsBecomeStatementSums(t *testing.T) {
	body := []byte(`{"id":"123","q":"SELECT 1","calls":"4","ms":"250","read_rows":"10","mem":"2048","errors":"1"}
{"id":"456","q":"SELECT 2","calls":2,"ms":5,"read_rows":0,"mem":0,"errors":0}
`)
	r := &sink.Recorder{}
	if err := EmitClickHouseQueries(r, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	wantNames(t, r, "clickhouse.statement.calls", "clickhouse.statement.total_time",
		"clickhouse.statement.read_rows", "clickhouse.statement.memory", "clickhouse.statement.errors")
	if v, _ := value(r, "clickhouse.statement.total_time"); v != 250 {
		t.Fatalf("total_time %v", v)
	}
	if err := EmitClickHouseQueries(r, []byte("not json\n"), time.Now()); err == nil {
		t.Fatal("garbage must fail")
	}
}
