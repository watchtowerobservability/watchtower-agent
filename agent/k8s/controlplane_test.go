package k8s

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const apiMetrics = `# TYPE apiserver_request_total counter
apiserver_request_total{verb="GET",code="200"} 42
# TYPE etcd_server_has_leader gauge
etcd_server_has_leader 1
`

func TestControlPlaneScrapeUsesServiceAccountToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(apiMetrics))
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp, err := NewControlPlane(ControlPlaneConfig{TokenFile: tok, CAFile: "/nonexistent", InsecureTLS: true}, srv.URL, "prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	cp.Scrape(context.Background(), rec, time.Now())
	if gotAuth != "Bearer sa-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	s := find(rec, "apiserver_request_total")
	if s == nil || s.Value != 42 || s.Attrs["verb"] != "GET" || s.Attrs["component"] != "apiserver" {
		t.Fatalf("apiserver_request_total = %+v", s)
	}
	if s.Attrs["resource.k8s.cluster.name"] != "prod" {
		t.Fatalf("cluster resource attribute missing: %+v", s.Attrs)
	}
	if find(rec, "etcd_server_has_leader") == nil || find(rec, "up").Value != 1 {
		t.Fatal("original names and up gauge expected")
	}
}

func TestEtcdNeedsClientCert(t *testing.T) {
	_, err := NewControlPlane(ControlPlaneConfig{EtcdTargets: []string{"https://10.0.0.5:2379/metrics"}}, "https://x", "", nil)
	if !errors.Is(err, ErrEtcdNeedsClientCert) {
		t.Fatalf("err = %v", err)
	}
	// A Secret directory without the key pair is refused too.
	_, err = NewControlPlane(ControlPlaneConfig{EtcdTargets: []string{"etcd"}, EtcdClientCertSecret: t.TempDir()}, "https://x", "", nil)
	if err == nil {
		t.Fatal("missing tls.crt/tls.key must fail")
	}
}

func TestControlPlaneURLsFromStaticPods(t *testing.T) {
	mk := func(name, comp string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system", Labels: map[string]string{"component": comp}},
			Status: corev1.PodStatus{PodIP: "10.0.0.5", Phase: corev1.PodRunning}}
	}
	pods := []*corev1.Pod{mk("s", "kube-scheduler"), mk("c", "kube-controller-manager")}
	if got := ControlPlaneURLs(pods, "scheduler"); len(got) != 1 || got[0] != "https://10.0.0.5:10259/metrics" {
		t.Fatalf("scheduler = %v", got)
	}
	if got := ControlPlaneURLs(pods, "etcd"); len(got) != 0 {
		t.Fatalf("etcd = %v", got)
	}
}
