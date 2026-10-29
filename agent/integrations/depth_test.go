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

func TestExporterScrapesPrefixedFamilies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/metrics" || r.Header.Get("X-Vault-Token") != "tok" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, "# TYPE vault_core_unsealed gauge\nvault_core_unsealed 1\n# TYPE other_total counter\nother_total 5\n"+
			"# TYPE vault_token_creation counter\nvault_token_creation{auth=\"ldap\"} 7\n")
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rec := &sink.Recorder{}
	cfg := fmt.Sprintf(`{"url":%q,"token":"tok"}`, srv.URL+"/v1/sys/metrics")
	_ = Vault(ctx, json.RawMessage(cfg), rec)
	wantNames(t, rec, "vault_core_unsealed", "vault_token_creation", "wt.integration.up")
	if rec.Names()["other_total"] {
		t.Fatal("a family outside the prefixes must not be forwarded")
	}
}

func TestExporterConfigRejectsBadURLAndUnknownKey(t *testing.T) {
	for _, raw := range []string{`{"url":"ftp://x"}`, `{"url":"http://x","passwrd":"a"}`, `{}`} {
		if err := ValidateConfig("mssql", json.RawMessage(raw)); err == nil {
			t.Errorf("%s must be refused", raw)
		}
	}
	if err := ValidateConfig("mssql", json.RawMessage(`{"url":"http://127.0.0.1:9399/metrics"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestActiveMQQueueTopology(t *testing.T) {
	rs := []jolokiaResp{{Status: 200, Value: json.RawMessage(`{
	 "org.apache.activemq:brokerName=b1,destinationName=orders,destinationType=Queue,type=Broker":{"QueueSize":12,"ConsumerCount":2,"EnqueueCount":100},
	 "org.apache.activemq:brokerName=b1,destinationName=audit,destinationType=Queue,type=Broker":{"QueueSize":1,"ConsumerCount":0}}`)}}
	rs[0].Request.MBean = activemqReads[0].MBean
	rec := &sink.Recorder{}
	emitActiveMQ(rec, rs, time.Now())
	for _, s := range rec.Samples {
		if s.Name == "activemq.queue.size" && s.Attrs["queue"] == "orders" && s.Attrs["broker"] == "b1" && s.Value == 12 {
			return
		}
	}
	t.Fatalf("no orders queue depth in %+v", rec.Samples)
}

func TestJMXFlattensCompositeAttributes(t *testing.T) {
	rs := []jolokiaResp{{Status: 200, Value: json.RawMessage(`{"HeapMemoryUsage":{"used":10,"max":20}}`)}}
	rs[0].Request.MBean = "java.lang:type=Memory"
	rec := &sink.Recorder{}
	emitJMX(rec, rs, time.Now())
	if v, ok := value(rec, "jmx.attribute"); !ok || v == 0 {
		t.Fatalf("no jmx.attribute: %+v", rec.Samples)
	}
}

func TestEmitDockerCountsStates(t *testing.T) {
	rec := &sink.Recorder{}
	body := `[{"Names":["/web"],"Image":"nginx","State":"running"},{"Names":["/job"],"Image":"busybox","State":"exited"}]`
	if err := EmitDocker(rec, []byte(body), time.Now()); err != nil {
		t.Fatal(err)
	}
	wantNames(t, rec, "docker.container.up", "docker.containers")
}

func TestNormalizePodConfigAndPodOnlyTargets(t *testing.T) {
	cfg := NormalizePodConfig("redis", map[string]any{"instances": []any{map[string]any{"host": "10.0.0.7", "port": float64(6379)}}, "interval": "20s"})
	if cfg["addr"] != "10.0.0.7:6379" || cfg["interval"] != "20s" {
		t.Fatalf("bad config %v", cfg)
	}
	if err := checkTargetsPod(cfg, "10.0.0.7"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]map[string]any{
		"other host":  {"addr": "10.0.0.8:6379"},
		"mysql other": {"dsn": "u:p@tcp(10.9.9.9:3306)/db"},
		"no target":   {"interval": "20s"},
		"url other":   {"url": "http://169.254.169.254/"},
	} {
		if err := checkTargetsPod(c, "10.0.0.7"); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if err := checkTargetsPod(map[string]any{"dsn": "u:p@tcp(10.0.0.7:3306)/db"}, "10.0.0.7"); err != nil {
		t.Fatal(err)
	}
}

func TestRunAnnotatedStartsAndStopsPodModules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "# TYPE ceph_health_status gauge\nceph_health_status 0\n")
	}))
	defer srv.Close()
	ip := strings.TrimPrefix(srv.URL, "http://")
	host := strings.Split(ip, ":")[0]
	ctx, cancel := context.WithCancel(context.Background())
	rec := &sink.Recorder{}
	list := func() []PodCheck {
		return []PodCheck{
			{Namespace: "ns", Pod: "p", UID: "u1", Container: "c", Module: "ceph", PodIP: host,
				Config: map[string]any{"url": srv.URL + "/metrics"}},
			{Namespace: "ns", Pod: "p", UID: "u1", Container: "c", Module: "listen", PodIP: host,
				Config: map[string]any{"url": srv.URL}},
		}
	}
	done := make(chan struct{})
	go func() { RunAnnotated(ctx, list, rec, 50*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !rec.Names()["ceph_health_status"] && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	wantNames(t, rec, "ceph_health_status")
	for _, s := range rec.Samples {
		if s.Name == "ceph_health_status" && s.Attrs["resource.k8s.pod.name"] == "" && !hasKeySuffix(s.Attrs, "k8s.pod.name") {
			t.Fatalf("pod identity missing: %v", s.Attrs)
		}
	}
}

func hasKeySuffix(m map[string]string, suffix string) bool {
	for k := range m {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}
