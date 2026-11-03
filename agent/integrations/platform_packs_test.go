package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// packFixture is a trimmed answer of each product at the path its module reads.
type packFixture struct {
	path, body string
	run        func(context.Context, json.RawMessage, sink.Sink) error
	auth       func(*http.Request) bool
}

func basicOK(r *http.Request) bool { u, p, ok := r.BasicAuth(); return ok && u == "u" && p == "p" }

var packFixtures = map[string]packFixture{
	"couchbase": {"/metrics", "# TYPE kv_ops counter\nkv_ops{bucket=\"b\",op=\"get\"} 10\n# TYPE kv_curr_items gauge\nkv_curr_items{bucket=\"b\"} 5\n" +
		"# TYPE kv_mem_used_bytes gauge\nkv_mem_used_bytes{bucket=\"b\"} 1024\n# TYPE go_goroutines gauge\ngo_goroutines 7\n", Couchbase, basicOK},
	"traefik": {"/metrics", "# TYPE traefik_service_requests_total counter\ntraefik_service_requests_total{code=\"200\",service=\"web\"} 9\n" +
		"# TYPE traefik_entrypoint_requests_total counter\ntraefik_entrypoint_requests_total{entrypoint=\"web\"} 9\n" +
		"# TYPE traefik_service_server_up gauge\ntraefik_service_server_up{service=\"web\",url=\"http://10.0.0.1\"} 1\n", Traefik, nil},
	"envoy": {"/stats/prometheus", "# TYPE envoy_server_live gauge\nenvoy_server_live 1\n# TYPE envoy_cluster_upstream_rq_total counter\n" +
		"envoy_cluster_upstream_rq_total{envoy_cluster_name=\"api\"} 4\n# TYPE envoy_cluster_membership_healthy gauge\nenvoy_cluster_membership_healthy{envoy_cluster_name=\"api\"} 2\n", Envoy, nil},
	"gitlab": {"/-/metrics", "# TYPE http_requests_total counter\nhttp_requests_total{method=\"get\",status=\"200\"} 3\n" +
		"# TYPE sidekiq_jobs_failed_total counter\nsidekiq_jobs_failed_total{worker=\"W\"} 1\n# TYPE puma_queued_connections gauge\npuma_queued_connections 0\n" +
		"# TYPE ruby_gc_stat_count gauge\nruby_gc_stat_count 3\n", GitLab, nil},
	"iis": {"/metrics", "# TYPE windows_iis_current_connections gauge\nwindows_iis_current_connections{site=\"Default\"} 3\n" +
		"# TYPE windows_iis_requests_total counter\nwindows_iis_requests_total{method=\"GET\",site=\"Default\"} 30\n" +
		"# TYPE windows_iis_not_found_errors_total counter\nwindows_iis_not_found_errors_total{site=\"Default\"} 2\n# TYPE windows_cpu_time_total counter\nwindows_cpu_time_total 9\n", IIS, nil},
	"kong": {"/metrics", "# TYPE kong_http_requests_total counter\nkong_http_requests_total{service=\"s\",route=\"r\",code=\"200\"} 5\n" +
		"# TYPE kong_datastore_reachable gauge\nkong_datastore_reachable 1\n# TYPE kong_upstream_target_health gauge\nkong_upstream_target_health{upstream=\"u\",target=\"t\",state=\"healthy\"} 1\n", Kong, nil},
	"minio": {"/minio/v2/metrics/cluster", "# TYPE minio_cluster_nodes_offline_total gauge\nminio_cluster_nodes_offline_total 0\n" +
		"# TYPE minio_cluster_capacity_usable_free_bytes gauge\nminio_cluster_capacity_usable_free_bytes 1e9\n# TYPE minio_s3_requests_total counter\nminio_s3_requests_total{api=\"getobject\"} 8\n",
		MinIO, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer k" }},
	"zookeeper": {"/metrics", "# TYPE znode_count gauge\nznode_count 40\n# TYPE outstanding_requests gauge\noutstanding_requests 0\n" +
		"# TYPE num_alive_connections gauge\nnum_alive_connections 6\n", Zookeeper, nil},
	"solr": {"/metrics", "# TYPE solr_metrics_core_requests_total counter\nsolr_metrics_core_requests_total{core=\"c1\",handler=\"/select\"} 12\n" +
		"# TYPE solr_metrics_core_errors_total counter\nsolr_metrics_core_errors_total{core=\"c1\",handler=\"/select\"} 1\n# TYPE solr_collections_live_nodes gauge\nsolr_collections_live_nodes 3\n", Solr, nil},
	"nomad": {"/v1/metrics", "# TYPE nomad_client_allocations_running gauge\nnomad_client_allocations_running 4\n" +
		"# TYPE nomad_nomad_blocked_evals_total_blocked gauge\nnomad_nomad_blocked_evals_total_blocked 0\n# TYPE nomad_nomad_job_summary_failed gauge\nnomad_nomad_job_summary_failed{exported_job=\"j\"} 0\n",
		Nomad, func(r *http.Request) bool {
			return r.Header.Get("X-Nomad-Token") == "k" && r.URL.Query().Get("format") == "prometheus"
		}},
	"istio": {"/metrics", "# TYPE pilot_xds_pushes counter\npilot_xds_pushes{type=\"cds\"} 20\n# TYPE pilot_xds gauge\npilot_xds{version=\"1.22\"} 12\n" +
		"# TYPE pilot_total_xds_rejects counter\npilot_total_xds_rejects 0\n", Istio, nil},
}

// Every new pack charts and documents only series its module really forwards, behind the product's
// own auth, and nothing outside the product's namespace.
func TestPlatformPacksChartWhatTheModulesEmit(t *testing.T) {
	packs := map[string]*Manifest{}
	for _, m := range loadAll(t) {
		packs[m.Name] = m
	}
	for name, fx := range packFixtures {
		m := packs[name]
		if m == nil || m.Module.Kind != name {
			t.Fatalf("%s: no manifest for the module", name)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != fx.path {
				http.NotFound(w, r)
				return
			}
			if fx.auth != nil && !fx.auth(r) {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, fx.body)
		}))
		rec := runPack(fx.run, fmt.Sprintf(`{"url":%q,"token":"k","username":"u","password":"p"}`, srv.URL))
		srv.Close()
		checkPack(t, name, m, rec, func(n string) bool {
			return strings.HasPrefix(n, name+"_") || strings.HasPrefix(n, "windows_iis_") ||
				strings.HasPrefix(n, "pilot_") || strings.HasPrefix(n, "solr_") || strings.HasPrefix(n, "nomad_")
		})
	}
}

func runPack(run func(context.Context, json.RawMessage, sink.Sink) error, cfg string) *sink.Recorder {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rec := &sink.Recorder{}
	_ = run(ctx, json.RawMessage(cfg), rec)
	return rec
}

func checkPack(t *testing.T, name string, m *Manifest, rec *sink.Recorder, inNamespace func(string) bool) {
	t.Helper()
	want := []string{"wt.integration.up"}
	for _, d := range m.Metrics {
		want = append(want, d.Name)
	}
	wantNames(t, rec, want...)
	if v, ok := value(rec, "wt.integration.up"); !ok || v != 1 {
		t.Errorf("%s: integration must report up=1, got %v", name, v)
	}
	for n := range rec.Names() {
		if n != "wt.integration.up" && !inNamespace(n) {
			t.Errorf("%s: forwarded %s outside the product namespace", name, n)
		}
	}
}

func TestTomcatPackReadsCatalinaMBeans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || !strings.Contains(string(b), "Catalina:type=ThreadPool") {
			http.Error(w, "bad read", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `[{"request":{"mbean":"Catalina:type=ThreadPool,name=*"},"status":200,"value":{"Catalina:name=\"http-nio-8080\",type=ThreadPool":{"currentThreadsBusy":3,"currentThreadCount":10,"maxThreads":200,"connectionCount":4}}},`+
			`{"request":{"mbean":"Catalina:type=GlobalRequestProcessor,name=*"},"status":200,"value":{"Catalina:name=\"http-nio-8080\",type=GlobalRequestProcessor":{"requestCount":50,"errorCount":2,"processingTime":900,"bytesSent":1,"bytesReceived":1}}},`+
			`{"request":{"mbean":"Catalina:type=Manager,host=*,context=*"},"status":200,"value":{"Catalina:context=/app,host=localhost,type=Manager":{"activeSessions":7,"rejectedSessions":0,"expiredSessions":1}}}]`)
	}))
	defer srv.Close()
	var m *Manifest
	for _, x := range loadAll(t) {
		if x.Name == "tomcat" {
			m = x
		}
	}
	if m == nil {
		t.Fatal("no tomcat manifest")
	}
	rec := runPack(Tomcat, fmt.Sprintf(`{"url":%q}`, srv.URL))
	checkPack(t, "tomcat", m, rec, func(n string) bool { return strings.HasPrefix(n, "tomcat.") })
	for _, s := range rec.Samples {
		if s.Name == "tomcat.threads.busy" && (s.Value != 3 || s.Attrs["connector"] != "http-nio-8080") {
			t.Fatalf("busy threads: %+v", s)
		}
		if s.Name == "tomcat.sessions.active" && s.Attrs["context"] != "/app" {
			t.Fatalf("sessions carry the context: %+v", s)
		}
	}
}

func TestJenkinsPackReadsTheJSONAPI(t *testing.T) {
	now := time.Now()
	since := now.Add(-20 * time.Minute).UnixMilli()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !basicOK(r) {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/computer/api/json":
			fmt.Fprint(w, `{"busyExecutors":2,"totalExecutors":4,"computer":[{"displayName":"built-in","offline":false},{"displayName":"agent-1","offline":true}]}`)
		case "/queue/api/json":
			fmt.Fprintf(w, `{"items":[{"stuck":true,"blocked":false,"inQueueSince":%d},{"stuck":false,"blocked":true,"inQueueSince":0}]}`, since)
		case "/api/json":
			fmt.Fprint(w, `{"jobs":[{"name":"build","color":"red","lastBuild":{"duration":61000,"result":"FAILURE","timestamp":1}},{"name":"new","color":"notbuilt","lastBuild":null},{"name":"run","lastBuild":{"duration":5,"result":null}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var m *Manifest
	for _, x := range loadAll(t) {
		if x.Name == "jenkins" {
			m = x
		}
	}
	if m == nil {
		t.Fatal("no jenkins manifest")
	}
	rec := runPack(Jenkins, fmt.Sprintf(`{"url":%q,"username":"u","password":"p"}`, srv.URL))
	checkPack(t, "jenkins", m, rec, func(n string) bool { return strings.HasPrefix(n, "jenkins.") })
	got := map[string]float64{}
	builds := 0
	for _, s := range rec.Samples {
		got[s.Name] = s.Value
		if s.Name == "jenkins.job.last_build.success" {
			builds++
			if s.Attrs["job"] != "build" || s.Attrs["result"] != "failure" || s.Value != 0 {
				t.Fatalf("last build: %+v", s)
			}
		}
	}
	if builds != 1 || got["jenkins.nodes.offline"] != 1 || got["jenkins.queue.size"] != 2 || got["jenkins.queue.stuck"] != 1 ||
		got["jenkins.job.last_build.duration"] != 61 || got["jenkins.queue.oldest_wait"] < 1100 {
		t.Fatalf("jenkins series: %v (builds %d)", got, builds)
	}
}
