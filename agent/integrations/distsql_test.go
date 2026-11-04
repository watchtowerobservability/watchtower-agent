package integrations

import (
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestCockroachDBRoundAndStatements(t *testing.T) {
	var r sink.Recorder
	now := time.Now()
	EmitCRDB(&r, "nodes", []map[string]string{{"live": "2", "total": "3"}}, now)
	EmitCRDB(&r, "stores", []map[string]string{{"node": "1", "store": "1", "ranges": "120", "unavailable": "0",
		"underreplicated": "4", "leases": "40", "capacity": "1000", "available": "250"}}, now)
	if v, _ := value(&r, "cockroachdb.ranges.underreplicated"); v != 4 {
		t.Fatalf("underreplicated %v", v)
	}
	if v, _ := value(&r, "cockroachdb.capacity.utilization"); v != 0.75 {
		t.Fatalf("capacity %v", v)
	}
	var d dbm.Deltas
	row := func(calls, ms string) []map[string]string {
		return []map[string]string{{"id": "a1b2", "db": "bank", "q": "SELECT * FROM accounts WHERE id = $1",
			"calls": calls, "total_ms": ms, "rows_n": calls, "rows_read": calls}}
	}
	EmitCRDBStatements(&r, &d, row("10", "50"), now)
	top := EmitCRDBStatements(&r, &d, row("20", "150"), now)
	if len(top) != 1 || top[0].MeanMs != 10 {
		t.Fatalf("%+v", top)
	}
}

func TestTiDBStoresStatementsDeadlocks(t *testing.T) {
	var r sink.Recorder
	now := time.Now()
	EmitTiDBStores(&r, []map[string]string{{"id": "1", "addr": "tikv-0:20160", "state": "Up", "cap": "1TiB",
		"avail": "256GiB", "leaders": "300", "regions": "900"}}, now)
	if v, _ := value(&r, "tidb.store.capacity.utilization"); v != 0.75 {
		t.Fatalf("utilization %v", v)
	}
	if v, _ := value(&r, "tidb.store.up"); v != 1 {
		t.Fatalf("up %v", v)
	}
	var d dbm.Deltas
	row := func(calls string) []map[string]string {
		return []map[string]string{{"db": "app", "digest": "d1", "q": "select * from t where a = ?", "calls": calls,
			"total_ms": calls, "rows_n": "1", "keys_processed": "10", "keys_total": calls}}
	}
	EmitTiDBStatements(&r, &d, row("5"), now)
	if top := EmitTiDBStatements(&r, &d, row("9"), now); len(top) != 1 || top[0].Delta.BlksRead != 4 {
		t.Fatalf("%+v", top)
	}
	seen := map[string]bool{}
	dl := []map[string]string{
		{"inst": "tidb-0:10080", "id": "7", "at": "2026-11-02 10:00:00", "trx": "100", "holder": "200",
			"q": "update t set v = 5 where id = 1", "key_info": `{"db_name":"app","table_name":"t","handle_value":"secret-handle"}`},
		{"inst": "tidb-0:10080", "id": "7", "at": "2026-11-02 10:00:00", "trx": "200", "holder": "100",
			"q": "update t set v = 6 where id = 2", "key_info": `{"table_name":"t","index_name":"PRIMARY"}`},
	}
	var dr sink.Recorder
	EmitTiDBDeadlocks(&dr, dl, seen, now)
	EmitTiDBDeadlocks(&dr, dl, seen, now) // already reported
	if len(dr.Samples) != 1 || strings.Contains(dr.Samples[0].Body, "secret-handle") || strings.Contains(dr.Samples[0].Body, "v = 5") ||
		!strings.Contains(dr.Samples[0].Body, `"table":"t"`) {
		t.Fatalf("%+v", dr.Samples)
	}
}

func TestYugabyteDBASHAndTablets(t *testing.T) {
	var r sink.Recorder
	now := time.Now()
	newest := EmitYBASH(&r, []map[string]string{
		{"db": "yugabyte", "class": "TServerWait", "event": "StorageRead", "n": "60", "newest": "2026-11-02T10:00:29.5Z"},
		{"db": "yugabyte", "class": "", "event": "", "n": "30", "newest": "2026-11-02T10:00:28Z"},
	}, 30*time.Second, now)
	if v, _ := value(&r, "db.activity.sessions"); v != 2 {
		t.Fatalf("sessions %v", v)
	}
	if r.Samples[1].Attrs["db.wait_event_type"] != "CPU" || newest.Second() != 29 {
		t.Fatalf("%+v %v", r.Samples[1].Attrs, newest)
	}
	EmitYB(&r, "servers", []map[string]string{{"host": "yb-0", "conns": "12", "type": "primary"}, {"host": "yb-1", "conns": "3", "type": "primary"}}, now)
	if v, _ := value(&r, "yugabytedb.servers"); v != 2 {
		t.Fatalf("servers %v", v)
	}
}
