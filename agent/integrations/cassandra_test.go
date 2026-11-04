package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// A Jolokia bulk reply as Cassandra 4.1 answers the pattern reads (trimmed to one table).
const cassandraJolokiaFixture = `[
{"request":{"mbean":"org.apache.cassandra.metrics:type=Table,keyspace=*,scope=*,name=ReadLatency"},"status":200,"value":{
 "org.apache.cassandra.metrics:keyspace=shop,name=ReadLatency,scope=orders,type=Table":{"Count":1000,"99thPercentile":2346.8,"Max":9000},
 "org.apache.cassandra.metrics:keyspace=system,name=ReadLatency,scope=local,type=Table":{"Count":5,"99thPercentile":10}}},
{"request":{"mbean":"org.apache.cassandra.metrics:type=Table,keyspace=*,scope=*,name=TombstoneScannedHistogram"},"status":200,"value":{
 "org.apache.cassandra.metrics:keyspace=shop,name=TombstoneScannedHistogram,scope=orders,type=Table":{"99thPercentile":1200,"Max":5000}}},
{"request":{"mbean":"org.apache.cassandra.metrics:type=Compaction,name=*"},"status":200,"value":{
 "org.apache.cassandra.metrics:name=PendingTasks,type=Compaction":{"Value":17},
 "org.apache.cassandra.metrics:name=BytesCompacted,type=Compaction":{"Count":123456}}},
{"request":{"mbean":"org.apache.cassandra.metrics:type=ClientRequest,scope=*,name=*"},"status":200,"value":{
 "org.apache.cassandra.metrics:name=Timeouts,scope=Read,type=ClientRequest":{"Count":3},
 "org.apache.cassandra.metrics:name=Latency,scope=Write,type=ClientRequest":{"Count":50,"99thPercentile":800}}},
{"request":{"mbean":"org.apache.cassandra.metrics:type=ThreadPools,path=*,scope=*,name=*"},"status":200,"value":{
 "org.apache.cassandra.metrics:name=PendingTasks,path=request,scope=MutationStage,type=ThreadPools":{"Value":40}}},
{"request":{"mbean":"org.apache.cassandra.metrics:type=DroppedMessage,scope=*,name=Dropped"},"status":200,"value":{
 "org.apache.cassandra.metrics:name=Dropped,scope=MUTATION,type=DroppedMessage":{"Count":2}}}]`

func TestCassandraJolokia(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, cassandraJolokiaFixture)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rec := &sink.Recorder{}
	_ = Cassandra(ctx, json.RawMessage(fmt.Sprintf(`{"url":%q}`, srv.URL+"/jolokia")), rec)
	wantNames(t, rec, "cassandra.table.read.latency.p99", "cassandra.table.reads", "cassandra.table.tombstones_scanned.p99",
		"cassandra.compaction.pending", "cassandra.compaction.bytes", "cassandra.client_request.timeouts",
		"cassandra.client_request.latency.p99", "cassandra.thread_pool.pending", "cassandra.dropped_messages")
	for _, s := range rec.Samples {
		if s.Attrs["db.namespace"] == "system" {
			t.Fatal("system keyspaces are left out")
		}
		if s.Name == "cassandra.table.tombstones_scanned.max" && (s.Value != 5000 || s.Attrs["db.collection.name"] != "orders") {
			t.Fatalf("%+v", s)
		}
		if s.Name == "cassandra.thread_pool.pending" && s.Attrs["thread_pool"] != "MutationStage" {
			t.Fatalf("%+v", s)
		}
	}
}
