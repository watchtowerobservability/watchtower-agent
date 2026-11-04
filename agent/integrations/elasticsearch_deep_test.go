package integrations

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Trimmed recorded replies of Elasticsearch 8.13.
const esNodeStatsFixture = `{"nodes":{"Xy1":{"name":"es-1","indices":{"search":{"query_total":120,"query_time_in_millis":900,"open_contexts":2},
"indexing":{"index_total":50,"index_time_in_millis":70}},"thread_pool":{"write":{"queue":4,"active":2,"rejected":17},"ml_utility":{"queue":0}},
"jvm":{"mem":{"heap_used_percent":81},"gc":{"collectors":{"old":{"collection_count":3,"collection_time_in_millis":400}}}},
"breakers":{"parent":{"tripped":1}}}}}`

const esExplainFixture = `{"index":"orders","shard":0,"primary":false,"current_state":"unassigned",
"unassigned_info":{"reason":"NODE_LEFT"},"can_allocate":"no","allocate_explanation":"cannot allocate because allocation is not permitted to any of the nodes",
"node_allocation_decisions":[{"node_name":"es-1","deciders":[{"decider":"same_shard","decision":"NO","explanation":"a copy of this shard is already allocated to this node"}]},
{"node_name":"es-2","deciders":[{"decider":"disk_threshold","decision":"NO","explanation":"the node is above the high watermark"}]}]}`

const esTasksFixture = `{"nodes":{"Xy1":{"name":"es-1","tasks":{
"Xy1:1":{"action":"indices:data/read/search","description":"indices[orders], search_type[QUERY_THEN_FETCH], source[{\"query\":{\"term\":{\"email\":\"a@b.c\"}}}]","running_time_in_nanos":4500000000,"cancellable":true},
"Xy1:2":{"action":"indices:data/read/search[phase/query]","description":"shardId[[orders][0]]","running_time_in_nanos":4400000000,"parent_task_id":"Xy1:1"},
"Xy1:3":{"action":"indices:data/write/bulk","description":"requests[10], indices[logs]","running_time_in_nanos":2000000}}}}}`

const esHotFixture = "::: {es-1}{Xy1}\n   Hot threads at 2026-11-02T10:00:00Z, interval=500ms, busiestThreads=3:\n\n" +
	"   87.3% [cpu=87.3%, other=0.0%] (436.4ms out of 500ms) cpu usage by thread 'elasticsearch[es-1][search][T#3]'\n" +
	"     10/10 snapshots sharing following 2 elements\n"

func TestElasticsearchDeep(t *testing.T) {
	now := time.Now()
	rec := &sink.Recorder{}
	var ns esNodeStats
	if err := json.Unmarshal([]byte(esNodeStatsFixture), &ns); err != nil {
		t.Fatal(err)
	}
	EmitESNodes(rec, ns, now)
	shards := []map[string]string{{"index": "orders", "prirep": "p", "state": "STARTED"},
		{"index": "orders", "prirep": "r", "state": "UNASSIGNED", "unassigned.reason": "NODE_LEFT"}}
	if n := EmitESShards(rec, shards, now); n != 1 {
		t.Fatal(n)
	}
	var ex map[string]any
	_ = json.Unmarshal([]byte(esExplainFixture), &ex)
	EmitESAllocation(rec, "elasticsearch", ex, now)
	var tasks esTasks
	if err := json.Unmarshal([]byte(esTasksFixture), &tasks); err != nil {
		t.Fatal(err)
	}
	EmitESTasks(rec, "opensearch", tasks, now)
	EmitESHotThreads(rec, "elasticsearch", esHotFixture, now)
	wantNames(t, rec, "elasticsearch.node.search.query_time", "elasticsearch.node.thread_pool.rejected", "elasticsearch.node.jvm.heap_used_percent",
		"elasticsearch.node.jvm.gc.time", "elasticsearch.node.breaker.tripped", "elasticsearch.shards", "elasticsearch.shards.unassigned",
		"elasticsearch.tasks.slow", "elasticsearch.hot_threads.peak_cpu")
	kinds := map[string]int{}
	for _, s := range rec.Samples {
		if s.Name == "elasticsearch.node.thread_pool.queue" && s.Attrs["thread_pool"] == "ml_utility" {
			t.Fatal("internal pools are not reported")
		}
		if s.Name == "elasticsearch.tasks.slow" && s.Value != 1 {
			t.Fatalf("slow tasks %v (child and fast tasks must not count)", s.Value)
		}
		if s.Name != "" {
			continue
		}
		kinds[s.Attrs["event.name"]]++
		if strings.Contains(s.Body, "a@b.c") || strings.Contains(s.Body, "email") {
			t.Fatalf("query source leaked: %s", s.Body)
		}
		if s.Attrs["event.name"] == "db.query.sample" && (s.Attrs["db.namespace"] != "orders" || s.Attrs["db.system.name"] != "opensearch") {
			t.Fatalf("%+v", s.Attrs)
		}
		if s.Attrs["event.name"] == "db.shard" && !strings.Contains(s.Body, "high watermark") {
			t.Fatal(s.Body)
		}
	}
	if kinds["db.shard"] != 1 || kinds["db.query.sample"] != 1 || kinds["db.wait"] != 1 {
		t.Fatalf("samples %v", kinds)
	}
}
