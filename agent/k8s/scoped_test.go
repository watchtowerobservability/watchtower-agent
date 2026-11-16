package k8s

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestScopeParsing(t *testing.T) {
	t.Setenv(scopeEnvVar, "")
	if _, err := (&ScopedConfig{}).Scope(); err == nil {
		t.Fatal("no namespaces must be an error, never cluster-wide")
	}
	t.Setenv(scopeEnvVar, " b, a ,b,kube-system")
	c := ScopedConfig{ExcludeNamespaces: []string{"kube-system"}}
	got, err := c.Scope()
	if err != nil || strings.Join(got, ",") != "a,b" {
		t.Fatalf("env scope = %v %v", got, err)
	}
	c = ScopedConfig{Namespaces: []string{"x"}}
	if got, _ := c.Scope(); len(got) != 1 || got[0] != "x" {
		t.Fatalf("config wins over env: %v", got)
	}
	c.Selector = "app.kubernetes.io/part-of=myapp"
	if _, err := c.Scope(); err != nil {
		t.Fatal(err)
	}
	c.Selector = "a in ("
	if _, err := c.Scope(); err == nil {
		t.Fatal("bad selector accepted")
	}
}

func TestMetricsPathIsNamespaced(t *testing.T) {
	p := podMetricsPath("shop", "app=web")
	if p != "/apis/metrics.k8s.io/v1beta1/namespaces/shop/pods?labelSelector=app%3Dweb" {
		t.Fatal(p)
	}
	if strings.Contains(podMetricsPath("a/b", ""), "a/b") {
		t.Fatal("namespace not escaped")
	}
}

func scopedPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: "u-" + "1"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", Ready: true, RestartCount: 3,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}}}
}

func TestPodMetricsMapping(t *testing.T) {
	l := &podMetricsList{}
	body := `{"items":[{"metadata":{"name":"web","namespace":"shop"},"containers":[{"name":"app","usage":{"cpu":"250m","memory":"64Mi"}}]}]}`
	if err := json.Unmarshal([]byte(body), l); err != nil {
		t.Fatal(err)
	}
	s := summaryFromMetrics(l, func(ns, n string) (string, bool) { return "u1", ns == "shop" })
	rec := &sink.Recorder{}
	Emit(rec, s, nil, func(PodRef) map[string]string { return map[string]string{"k8s.pod.name": "web"} }, time.Now())
	n := rec.Names()
	for _, want := range []string{"k8s.container.cpu.usage", "k8s.container.memory.working_set", "k8s.pod.cpu.usage"} {
		if !n[want] {
			t.Fatalf("missing %s in %v", want, n)
		}
	}
	for _, sm := range rec.Snapshot() {
		if sm.Name == "k8s.container.cpu.usage" && sm.Value != 0.25 {
			t.Fatalf("cpu = %v", sm.Value)
		}
	}
}

func TestScopedPodStatusSameNames(t *testing.T) {
	rec := &sink.Recorder{}
	c := &cluster{out: rec}
	c.emitPodList(context.Background(), rec, time.Now(), []*corev1.Pod{scopedPod("shop", "web"), scopedPod("kube-system", "dns")})
	n := rec.Names()
	for _, want := range []string{"k8s.pod.phase", "k8s.pod.ready", "k8s.container.restarts", "k8s.container.ready"} {
		if !n[want] {
			t.Fatalf("missing %s", want)
		}
	}
	found := false
	for _, sm := range rec.Snapshot() {
		if sm.Attrs["k8s.container.status.reason"] == "OOMKilled" {
			found = true
		}
	}
	if !found {
		t.Fatal("OOMKilled reason not reported")
	}
	c.cfg.ExcludeNamespaces = []string{"kube-system"}
	rec2 := &sink.Recorder{}
	c.emitPodList(context.Background(), rec2, time.Now(), []*corev1.Pod{scopedPod("kube-system", "dns")})
	if len(rec2.Snapshot()) != 0 {
		t.Fatal("excluded namespace reported")
	}
}

func TestWantedLogsAndLineTime(t *testing.T) {
	p := scopedPod("shop", "web")
	p.Status.ContainerStatuses = append(p.Status.ContainerStatuses,
		corev1.ContainerStatus{Name: "wait", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{}}},
		corev1.ContainerStatus{Name: "run", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}})
	got := wantedLogs([]*corev1.Pod{p})
	if len(got) != 1 || got[0].ctr != "run" {
		t.Fatalf("wanted = %+v", got)
	}
	at, text := splitLogTime("2026-11-16T10:00:00.123456789Z hello world")
	if text != "hello world" || at.Nanosecond() != 123456789 {
		t.Fatal(at, text)
	}
}

func TestScopedNeverCallsClusterScopedAPIs(t *testing.T) {
	in, out := scopedPod("shop", "web"), scopedPod("other", "x")
	cs := fake.NewSimpleClientset(in, out)
	var paths []string
	fetch := func(_ context.Context, p string) ([]byte, error) {
		paths = append(paths, p)
		return []byte(`{"items":[]}`), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	rec := &sink.Recorder{}
	if err := runScoped(ctx, ScopedConfig{Selector: "app=web"}, []string{"shop"}, cs, fetch, rec); err != nil {
		t.Fatal(err)
	}
	if len(cs.Actions()) == 0 {
		t.Fatal("no API calls recorded")
	}
	for _, a := range cs.Actions() {
		if a.GetNamespace() != "shop" {
			t.Fatalf("call outside scope: %s %s ns=%q", a.GetVerb(), a.GetResource().Resource, a.GetNamespace())
		}
		if a.GetResource().Resource == "nodes" || a.GetResource().Resource == "namespaces" {
			t.Fatalf("cluster-scoped resource %s", a.GetResource().Resource)
		}
	}
	if len(paths) == 0 || !strings.HasPrefix(paths[0], "/apis/metrics.k8s.io/v1beta1/namespaces/shop/pods") {
		t.Fatalf("metrics paths = %v", paths)
	}
	for _, sm := range rec.Snapshot() {
		if sm.Attrs[sink.ResourcePrefix+"k8s.namespace.name"] == "other" {
			t.Fatal("pod of another namespace reported")
		}
	}
}
