package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// vectorFixtures are trimmed /metrics answers of each product.
var vectorFixtures = map[string]string{
	"qdrant": "# TYPE collections_total gauge\ncollections_total 2\n# TYPE collections_vector_total gauge\ncollections_vector_total 1200\n" +
		"# TYPE rest_responses_avg_duration_seconds gauge\nrest_responses_avg_duration_seconds{endpoint=\"/collections/{name}/points/search\",method=\"POST\"} 0.004\n" +
		"# TYPE rest_responses_fail_total counter\nrest_responses_fail_total{endpoint=\"/collections/{name}/points/search\",method=\"POST\"} 3\n" +
		"# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 9\n",
	"weaviate": "# TYPE object_count gauge\nobject_count{class_name=\"Doc\",shard_name=\"s1\"} 500\n# TYPE queries_durations_ms histogram\n" +
		"queries_durations_ms_bucket{class_name=\"Doc\",le=\"+Inf\"} 4\nqueries_durations_ms_sum{class_name=\"Doc\"} 40\nqueries_durations_ms_count{class_name=\"Doc\"} 4\n" +
		"# TYPE vector_index_size gauge\nvector_index_size{class_name=\"Doc\",shard_name=\"s1\"} 500\n",
	"milvus": "# TYPE milvus_proxy_search_vectors_count counter\nmilvus_proxy_search_vectors_count{node_id=\"1\"} 77\n" +
		"# TYPE milvus_proxy_sq_latency histogram\nmilvus_proxy_sq_latency_bucket{le=\"+Inf\"} 5\nmilvus_proxy_sq_latency_sum 50\nmilvus_proxy_sq_latency_count 5\n" +
		"# TYPE milvus_querynode_entity_num gauge\nmilvus_querynode_entity_num{collection_name=\"docs\"} 9000\n",
	"pinecone": "# TYPE pinecone_db_record_total gauge\npinecone_db_record_total{index_name=\"faq\"} 42\n" +
		"# TYPE pinecone_db_op_query_total counter\npinecone_db_op_query_total{index_name=\"faq\"} 10\n" +
		"# TYPE pinecone_db_op_query_duration_total counter\npinecone_db_op_query_duration_total{index_name=\"faq\"} 120\n",
}

var vectorModules = map[string]func(context.Context, json.RawMessage, sink.Sink) error{
	"qdrant": Qdrant, "weaviate": Weaviate, "milvus": Milvus, "pinecone": Pinecone,
}

// Each vector-database pack charts and documents only series its module really forwards: the
// module scrapes a product-shaped endpoint and every metric the manifest lists arrives.
func TestVectorDBPacksChartWhatTheModulesEmit(t *testing.T) {
	packs := map[string]*Manifest{}
	for _, m := range loadAll(t) {
		packs[m.Name] = m
	}
	for name, run := range vectorModules {
		m := packs[name]
		if m == nil || m.Module.Kind != name {
			t.Fatalf("%s: no manifest for the module", name)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/metrics" {
				http.NotFound(w, r)
				return
			}
			if name == "qdrant" && r.Header.Get("api-key") != "k" || name == "pinecone" && r.Header.Get("Authorization") != "Bearer k" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, vectorFixtures[name])
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		rec := &sink.Recorder{}
		u := srv.URL
		if name == "pinecone" {
			u += "/metrics" // a direct target; discovery is covered below
		}
		_ = run(ctx, json.RawMessage(fmt.Sprintf(`{"url":%q,"token":"k"}`, u)), rec)
		cancel()
		srv.Close()
		want := []string{"wt.integration.up"}
		for _, d := range m.Metrics {
			want = append(want, d.Name)
		}
		wantNames(t, rec, want...)
		if v, ok := value(rec, "wt.integration.up"); !ok || v != 1 {
			t.Errorf("%s: integration must report up=1, got %v", name, v)
		}
		for n := range rec.Names() {
			if n != "wt.integration.up" && !strings.HasPrefix(n, name+"_") {
				t.Errorf("%s: forwarded %s outside the product namespace", name, n)
			}
		}
	}
}

func TestPineconeDiscoveryYieldsHTTPSTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `[{"targets":["metrics.a.pinecone.io:443"],"labels":{"__metrics_path__":"/v1/p/metrics","__scheme__":"http"}},{"targets":["b.pinecone.io"],"labels":{}}]`)
	}))
	defer srv.Close()
	got, err := discover(context.Background(), exporterSpec{name: "pinecone"}, &ExporterConfig{URL: srv.URL + "/discovery", Token: "k"})
	if err != nil || strings.Join(got, " ") != "https://metrics.a.pinecone.io:443/v1/p/metrics https://b.pinecone.io/metrics" {
		t.Fatalf("targets: %v %v", got, err)
	}
	if _, err := discover(context.Background(), exporterSpec{name: "pinecone"}, &ExporterConfig{URL: srv.URL + "/discovery"}); err == nil {
		t.Fatal("a refused discovery must be an error")
	}
}
