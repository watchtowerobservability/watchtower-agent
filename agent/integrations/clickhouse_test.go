package integrations

import (
	"strings"
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

func TestClickHouseHealthRows(t *testing.T) {
	r := &sink.Recorder{}
	parts := []byte(`{"database":"wt","table":"spans","parts":"812","max_partition_parts":"301","rows":"9000000","bytes":"123456"}` + "\n")
	if err := EmitClickHouseHealth(r, "parts", parts, time.Now()); err != nil {
		t.Fatal(err)
	}
	reps := []byte(`{"database":"wt","table":"spans","is_readonly":1,"absolute_delay":"45","queue_size":"12","inserts_in_queue":"3","merges_in_queue":"9","active_replicas":1,"total_replicas":2}` + "\n")
	_ = EmitClickHouseHealth(r, "replicas", reps, time.Now())
	slow := []byte(`{"id":"99","q":"SELECT * FROM spans WHERE trace_id = 'abc' AND n IN (1, 2)","ms":"1200","read_rows":"5","mem":"10","error":0}` + "\n")
	_ = EmitClickHouseHealth(r, "slow", slow, time.Now())
	_ = EmitClickHouseHealth(r, "errors", []byte(`{"name":"MEMORY_LIMIT_EXCEEDED","total":"135096"}`), time.Now())
	wantNames(t, r, "clickhouse.errors", "clickhouse.table.parts", "clickhouse.table.max_partition_parts", "clickhouse.replica.readonly", "clickhouse.replica.delay")
	for _, s := range r.Samples {
		if s.Name == "clickhouse.table.max_partition_parts" && (s.Value != 301 || s.Attrs["db.collection.name"] != "spans") {
			t.Fatalf("%+v", s)
		}
		if s.Name == "clickhouse.errors" && (s.Value != 135096 || s.Attrs["error.type"] != "MEMORY_LIMIT_EXCEEDED") {
			t.Fatalf("%+v", s)
		}
		if s.Name == "clickhouse.replica.readonly" && s.Value != 1 {
			t.Fatalf("%+v", s)
		}
		if s.Name == "" && (s.Attrs["event.name"] != "db.query.sample" || s.Attrs["queryid"] != "99" ||
			!strings.Contains(s.Body, "trace_id = ? AND n IN (?+)") || strings.Contains(s.Body, "abc")) {
			t.Fatalf("%+v", s)
		}
	}
	if err := EmitClickHouseHealth(r, "parts", []byte("{"), time.Now()); err == nil {
		t.Fatal("garbage must fail")
	}
}
