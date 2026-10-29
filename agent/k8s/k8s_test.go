package k8s

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func ptr[T any](v T) *T { return &v }

func owner(kind, name, uid string) metav1.OwnerReference {
	return metav1.OwnerReference{Kind: kind, Name: name, UID: types.UID("uid-" + uid), Controller: ptr(true)}
}

func find(rec *sink.Recorder, name string) *sink.Sample {
	for _, s := range rec.Snapshot() {
		if s.Name == name {
			return &s
		}
	}
	return nil
}

func fixtureObjects() []runtime.Object {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop", UID: "dep-1", Labels: map[string]string{"app": "web"}},
		Spec: appsv1.DeploymentSpec{Replicas: ptr(int32(3)), Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: "shop/web:1.2",
				Env: []corev1.EnvVar{{Name: "DB_PASSWORD", Value: "hunter2"}},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
					Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")}},
			}}}}},
		Status: appsv1.DeploymentStatus{AvailableReplicas: 2},
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-7d9f8", Namespace: "shop", UID: "rs-1",
		OwnerReferences: []metav1.OwnerReference{owner("Deployment", "web", "dep-1")}}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-7d9f8-abcde", Namespace: "shop", UID: "pod-1",
			OwnerReferences: []metav1.OwnerReference{owner("ReplicaSet", "web-7d9f8", "rs-1")}},
		Spec: corev1.PodSpec{NodeName: "node1", Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true, RestartCount: 4,
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}},
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", UID: "node-1"},
		Status: corev1.NodeStatus{
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}, {Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse}},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("8Gi")}}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "nightly-1", Namespace: "shop", UID: "job-1"},
		Status: batchv1.JobStatus{Failed: 2, Active: 1}}
	return []runtime.Object{dep, rs, pod, node, job}
}

// start builds a cluster agent on the fake API and waits for its caches.
func start(t *testing.T, objs ...runtime.Object) (*cluster, *sink.Recorder, *fake.Clientset) {
	t.Helper()
	cs := fake.NewClientset(objs...)
	f := informers.NewSharedInformerFactory(cs, 0)
	rec := &sink.Recorder{}
	c, syncs, err := newCluster(f, ClusterConfig{ClusterName: "prod", EventsPerSec: 100}, rec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), syncs...) {
		t.Fatal("caches did not sync")
	}
	return c, rec, cs
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestKubeStateMetricsFromFake(t *testing.T) {
	c, rec, _ := start(t, fixtureObjects()...)
	c.emitState(context.Background(), time.Now())

	for name, want := range map[string]float64{
		"k8s.deployment.desired":   3,
		"k8s.deployment.available": 2,
		"k8s.pod.phase":            2, // Running
		"k8s.pod.ready":            1,
		"k8s.container.restarts":   4,
		"k8s.node.condition_ready": 1,
		"k8s.job.failed_pods":      2,
	} {
		s := find(rec, name)
		if s == nil {
			t.Fatalf("missing metric %s; have %v", name, rec.Names())
		}
		if s.Value != want {
			t.Errorf("%s = %v, want %v", name, s.Value, want)
		}
	}
	d := find(rec, "k8s.deployment.desired")
	if d.Attrs["resource.k8s.deployment.name"] != "web" || d.Attrs["resource.k8s.namespace.name"] != "shop" ||
		d.Attrs["resource.k8s.cluster.name"] != "prod" || d.Attrs["resource.k8s.deployment.uid"] != "dep-1" {
		t.Fatalf("deployment resource attrs: %v", d.Attrs)
	}
	if got := d.Attrs["resource.k8s.deployment.spec.image"]; got != "app=shop/web:1.2" {
		t.Fatalf("spec image attr: %q", got)
	}
	if got := d.Attrs["resource.k8s.deployment.spec.resources"]; got != "app:cpu_req=100m,mem_lim=128Mi" {
		t.Fatalf("spec resources attr: %q", got)
	}
	if d.Attrs["resource.k8s.deployment.spec.replicas"] != "3" || d.Attrs["resource.k8s.deployment.spec.labels"] != "app=web" {
		t.Fatalf("spec attrs: %v", d.Attrs)
	}
	r := find(rec, "k8s.container.restarts")
	if r.Attrs["k8s.container.name"] != "app" || r.Attrs["resource.host.name"] != "node1" {
		t.Fatalf("restart attrs: %v", r.Attrs)
	}
	if find(rec, "k8s.container.ready").Attrs["k8s.container.status.reason"] != "OOMKilled" {
		t.Fatal("last termination reason must be reported")
	}
	for _, s := range rec.Snapshot() {
		for k, v := range s.Attrs {
			if strings.HasPrefix(k, "wt.") || strings.HasPrefix(k, "resource.wt.") {
				t.Fatalf("agent must never stamp wt.* attributes: %s", k)
			}
			if strings.Contains(v, "hunter2") {
				t.Fatalf("env values must never be read: %s=%s", k, v)
			}
		}
	}
}

func TestEnvAndAnnotationsAreDroppedByTheTransform(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Annotations: map[string]string{
			"watchtower.dev/scrape": "true", "kubectl.kubernetes.io/last-applied-configuration": "{secret}"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Env: []corev1.EnvVar{{Name: "K", Value: "v"}},
			EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{}}}, Command: []string{"x"}}},
			Volumes: []corev1.Volume{{Name: "s"}}},
	}
	got, err := Trim(pod)
	if err != nil {
		t.Fatal(err)
	}
	p := got.(*corev1.Pod)
	if len(p.Spec.Containers[0].Env) != 0 || len(p.Spec.Containers[0].EnvFrom) != 0 || len(p.Spec.Containers[0].Command) != 0 || len(p.Spec.Volumes) != 0 {
		t.Fatalf("sensitive pod spec fields survived: %+v", p.Spec)
	}
	if len(p.Annotations) != 1 || p.Annotations["watchtower.dev/scrape"] != "true" {
		t.Fatalf("only our annotations are kept: %v", p.Annotations)
	}
}

func TestSpecChangeLogsObjectChange(t *testing.T) {
	_, rec, cs := start(t, fixtureObjects()...)
	time.Sleep(200 * time.Millisecond) // let the watches establish before the update
	dep, err := cs.AppsV1().Deployments("shop").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dep.Spec.Template.Spec.Containers[0].Image = "shop/web:1.3"
	if _, err := cs.AppsV1().Deployments("shop").Update(context.Background(), dep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	var s sink.Sample
	eventually(t, "k8s.object.change log", func() bool {
		for _, x := range rec.Snapshot() {
			if x.Sev != "" && x.Attrs["k8s.object.kind"] == "deployment" {
				s = x
				return true
			}
		}
		return false
	})
	if s.Attrs["resource.k8s.deployment.spec.image"] != "app=shop/web:1.3" || s.Attrs["k8s.object.change.fields"] != "image" {
		t.Fatalf("change record: %v", s.Attrs)
	}
	if !strings.Contains(s.Body, "app=shop/web:1.2 -> app=shop/web:1.3") {
		t.Fatalf("body must show old and new: %q", s.Body)
	}
}

func TestEventsBecomeLogs(t *testing.T) {
	now := metav1.NewTime(time.Now())
	old := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "web.1", Namespace: "shop", UID: "ev-1"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-7d9f8-abcde", Namespace: "shop", UID: "pod-1"},
		Reason:         "BackOff", Type: corev1.EventTypeWarning, Message: "Back-off restarting failed container",
		Count: 3, LastTimestamp: now,
	}
	stale := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "web.0", Namespace: "shop", UID: "ev-0"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-old", Namespace: "shop"},
		Reason:         "Pulled", Type: corev1.EventTypeNormal, Message: "old news", Count: 1, LastTimestamp: old,
	}
	_, rec, cs := start(t, ev, stale)
	time.Sleep(200 * time.Millisecond) // let the watches establish before the update below
	eventually(t, "event log", func() bool { return len(rec.Snapshot()) > 0 })
	time.Sleep(200 * time.Millisecond)
	logs := rec.Snapshot()
	if len(logs) != 1 {
		t.Fatalf("only the recent event is reported at start-up, got %d records", len(logs))
	}
	l := logs[0]
	want := map[string]string{
		"k8s.event.reason": "BackOff", "k8s.event.type": "Warning", "k8s.event.count": "3",
		"k8s.event.object.kind": "Pod", "k8s.event.object.name": "web-7d9f8-abcde",
		"k8s.event.object.namespace": "shop", "k8s.event.object.uid": "pod-1",
		"resource.k8s.namespace.name": "shop", "resource.k8s.cluster.name": "prod",
	}
	for k, v := range want {
		if l.Attrs[k] != v {
			t.Errorf("%s = %q, want %q", k, l.Attrs[k], v)
		}
	}
	if l.Sev != "WARN" || l.Body != "Back-off restarting failed container" {
		t.Fatalf("severity/body: %q %q", l.Sev, l.Body)
	}

	// A repeat with a higher count is reported again; the same count is not.
	ev.Count = 4
	if _, err := cs.CoreV1().Events("shop").Update(context.Background(), ev, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "repeat", func() bool { return len(rec.Snapshot()) == 2 })
}

func TestEventRateLimit(t *testing.T) {
	l := newLimiter(10) // burst 20
	now := time.Now()
	ok := 0
	for i := 0; i < 100; i++ {
		if l.allow(now) {
			ok++
		}
	}
	if ok != 20 || l.takeDropped() != 80 {
		t.Fatalf("burst allowed %d", ok)
	}
	if !l.allow(now.Add(time.Second)) {
		t.Fatal("tokens must refill")
	}
}

func TestOwnerChainEnrichment(t *testing.T) {
	cs := fake.NewClientset(
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-7d9f8", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{owner("Deployment", "web", "dep-1")}}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "report-28", Namespace: "shop",
			OwnerReferences: []metav1.OwnerReference{owner("CronJob", "report", "cj-1")}}},
	)
	look := NewAPILookup(cs)
	ctx := context.Background()

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-7d9f8-x", Namespace: "shop", UID: "pod-1",
		OwnerReferences: []metav1.OwnerReference{owner("ReplicaSet", "web-7d9f8", "rs-1")}},
		Spec: corev1.PodSpec{NodeName: "node1"}}
	a := PodAttrs(ctx, "prod", pod, look)
	for k, v := range map[string]string{
		"k8s.cluster.name": "prod", "k8s.namespace.name": "shop", "k8s.pod.name": "web-7d9f8-x", "k8s.pod.uid": "pod-1",
		"k8s.node.name": "node1", "k8s.replicaset.name": "web-7d9f8", "k8s.deployment.name": "web",
	} {
		if a[k] != v {
			t.Errorf("%s = %q, want %q", k, a[k], v)
		}
	}
	for k := range a {
		if k != "k8s.pod.uid" && strings.HasSuffix(k, ".uid") {
			t.Errorf("owners must not carry a uid (it would create an entity without spec): %s", k)
		}
	}

	job := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "report-28-x", Namespace: "shop",
		OwnerReferences: []metav1.OwnerReference{owner("Job", "report-28", "j-1")}}}
	if b := PodAttrs(ctx, "", job, look); b["k8s.job.name"] != "report-28" || b["k8s.cronjob.name"] != "report" {
		t.Fatalf("job chain: %v", b)
	}
	bare := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "static", Namespace: "kube-system"}}
	if b := PodAttrs(ctx, "", bare, look); len(b) != 3 {
		t.Fatalf("a pod without owners gets only its own identity: %v", b)
	}
	// A StatefulSet owner ends the chain without an API call.
	sts := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "shop",
		OwnerReferences: []metav1.OwnerReference{owner("StatefulSet", "db", "s-1")}}}
	if b := PodAttrs(ctx, "", sts, nil); b["k8s.statefulset.name"] != "db" {
		t.Fatalf("statefulset: %v", b)
	}
}

func TestScrapeAnnotationDiscovery(t *testing.T) {
	mk := func(name string, ann map[string]string, ip string, phase corev1.PodPhase, ports ...int32) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", UID: "u-" + "name", Annotations: ann},
			Status: corev1.PodStatus{PodIP: ip, Phase: phase}}
		c := corev1.Container{Name: "c"}
		for _, n := range ports {
			c.Ports = append(c.Ports, corev1.ContainerPort{ContainerPort: n})
		}
		p.Spec.Containers = []corev1.Container{c}
		return p
	}
	run := corev1.PodRunning
	pods := []*corev1.Pod{
		mk("b-explicit", map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/port": "9102",
			"watchtower.dev/path": "/stats", "watchtower.dev/integration": "redis"}, "10.0.0.2", run),
		mk("a-default", map[string]string{"watchtower.dev/scrape": "true"}, "10.0.0.1", run, 8080),
		mk("off", map[string]string{"watchtower.dev/scrape": "false"}, "10.0.0.3", run, 80),
		mk("none", nil, "10.0.0.4", run, 80),
		mk("pending", map[string]string{"watchtower.dev/scrape": "true"}, "", corev1.PodPending, 80),
		mk("bad-port", map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/port": "99999"}, "10.0.0.5", run),
		mk("bad-path", map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/path": "http://evil/x"}, "10.0.0.6", run, 80),
		mk("no-port", map[string]string{"watchtower.dev/scrape": "true"}, "10.0.0.7", run),
	}
	got := Discover(pods)
	if len(got) != 2 {
		t.Fatalf("want 2 targets, got %+v", got)
	}
	if got[0].Pod != "a-default" || got[0].URL() != "http://10.0.0.1:8080/metrics" {
		t.Fatalf("default port and path: %+v", got[0])
	}
	if got[1].URL() != "http://10.0.0.2:9102/stats" || got[1].Integration != "redis" {
		t.Fatalf("explicit annotations: %+v", got[1])
	}
}

func TestCheckTemplateAnnotationBindsModule(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cache-0", Namespace: "shop", Annotations: map[string]string{
			"ad.watchtower.dev/redis.checks": `{"redis":{"instances":[{"host":"%%host%%","port":"%%port%%"}]}}`,
			"ad.watchtower.dev/ghost.checks": `{"redis":{}}`, // no such container
			"ad.watchtower.dev/redis.bad":    `{"redis":{}}`, // not a .checks key
		}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "redis", Ports: []corev1.ContainerPort{{ContainerPort: 6379}}},
		}},
		Status: corev1.PodStatus{PodIP: "10.0.0.9", Phase: corev1.PodRunning},
	}
	got := DiscoverChecks([]*corev1.Pod{p})
	if len(got) != 1 || got[0].Module != "redis" || got[0].Container != "redis" {
		t.Fatalf("want one redis binding, got %+v", got)
	}
	inst := got[0].Config["instances"].([]any)[0].(map[string]any)
	if inst["host"] != "10.0.0.9" || inst["port"] != "6379" {
		t.Fatalf("templates not resolved: %v", inst)
	}
	p.Status.Phase = corev1.PodPending
	if len(DiscoverChecks([]*corev1.Pod{p})) != 0 {
		t.Fatal("a pod that is not running binds nothing")
	}
}

func TestNetworkPolicyChangeLogged(t *testing.T) {
	var r sink.Recorder
	c := &cluster{out: &r, lim: newLimiter(100)}
	oldP := &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "shop"},
		Spec: netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress}}}
	newP := oldP.DeepCopy()
	newP.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{}}
	c.onNetpolChange(oldP, newP)
	s := r.Snapshot()
	if len(s) != 1 || s[0].Attrs["k8s.object.kind"] != "networkpolicy" || !strings.Contains(s[0].Attrs["k8s.object.change.fields"], "ingress_rules") {
		t.Fatalf("change record: %+v", s)
	}
}

func TestLeaderElectionSingleActive(t *testing.T) {
	cs := fake.NewClientset()
	tm := Timing{LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 100 * time.Millisecond}
	var active, peak, started atomic.Int32
	var first atomic.Value // id of the replica that led first; the election, not the test, picks it
	leadAs := func(id string) func(context.Context) error {
		return func(ctx context.Context) error {
			first.CompareAndSwap(nil, id)
			n := active.Add(1)
			started.Add(1)
			for {
				if m := peak.Load(); n <= m || peak.CompareAndSwap(m, n) {
					break
				}
			}
			<-ctx.Done()
			active.Add(-1)
			return nil
		}
	}
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	defer stopA()
	go func() { _ = RunElected(ctxA, cs, "wt", "wt-cluster-agent", "a", tm, leadAs("a")) }()
	go func() { _ = RunElected(ctxB, cs, "wt", "wt-cluster-agent", "b", tm, leadAs("b")) }()

	eventually(t, "a leader", func() bool { return active.Load() == 1 })
	time.Sleep(time.Second)
	if active.Load() != 1 || started.Load() != 1 {
		t.Fatalf("exactly one replica may lead: active=%d started=%d", active.Load(), started.Load())
	}

	// The leader goes away (releasing the lease); the other replica takes over, still alone.
	if first.Load() == "a" {
		stopA()
	} else {
		stopB()
	}
	eventually(t, "failover", func() bool { return started.Load() == 2 })
	time.Sleep(300 * time.Millisecond)
	if active.Load() != 1 || peak.Load() != 1 {
		t.Fatalf("never two at once: active=%d max=%d", active.Load(), peak.Load())
	}
}

func TestKubeletSummaryParse(t *testing.T) {
	f, err := os.Open("testdata/summary.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := ParseSummary(f)
	if err != nil {
		t.Fatal(err)
	}
	if s.Node.NodeName != "node1" || len(s.Pods) != 1 || len(s.Pods[0].Containers) != 2 {
		t.Fatalf("parsed: %+v", s)
	}
	rec := &sink.Recorder{}
	Emit(rec, s, map[string]string{"k8s.node.name": "node1"}, func(r PodRef) map[string]string {
		return map[string]string{"k8s.pod.uid": r.UID, "k8s.pod.name": r.Name, "k8s.namespace.name": r.Namespace, "k8s.deployment.name": "web"}
	}, time.Now())

	for _, n := range []string{"k8s.node.cpu.usage", "k8s.node.memory.working_set", "k8s.pod.cpu.usage", "k8s.pod.cpu.time",
		"k8s.pod.memory.usage", "k8s.pod.network.io", "k8s.container.cpu.usage", "k8s.container.memory.working_set",
		"k8s.container.filesystem.usage", "k8s.pod.filesystem.usage"} {
		if !rec.Names()[n] {
			t.Errorf("missing %s", n)
		}
	}
	if p := find(rec, "k8s.pod.cpu.usage"); p.Value != 0.25 || p.Attrs["resource.k8s.deployment.name"] != "web" || p.Attrs["resource.k8s.pod.uid"] != "uid-web-1" {
		t.Fatalf("pod cpu: %+v", p)
	}
	// "sidecar" reported only some fields: absent fields give no point.
	n := 0
	for _, s := range rec.Snapshot() {
		if s.Name == "k8s.container.memory.usage" && s.Attrs["k8s.container.name"] == "sidecar" {
			n++
		}
	}
	if n != 0 {
		t.Fatal("a missing field must not become a zero")
	}
}

func TestPodLogPathAndCRI(t *testing.T) {
	ns, pod, uid, ctr, ok := ParsePodLogPath("/var/log/pods", "/var/log/pods/shop_web-1_abc-123/app/0.log")
	if !ok || ns != "shop" || pod != "web-1" || uid != "abc-123" || ctr != "app" {
		t.Fatalf("path: %v %v %v %v %v", ns, pod, uid, ctr, ok)
	}
	if _, _, _, _, ok := ParsePodLogPath("/var/log/pods", "/etc/passwd"); ok {
		t.Fatal("paths outside the pod log dir must not parse")
	}
	at, stream, text, partial, ok := ParseCRI("2026-10-29T10:00:00.123456789Z stderr F boom: failed")
	if !ok || stream != "stderr" || text != "boom: failed" || partial || at.Year() != 2026 {
		t.Fatalf("cri: %v %v %q %v %v", at, stream, text, partial, ok)
	}
	if _, _, _, _, ok := ParseCRI("not a cri line"); ok {
		t.Fatal("garbage must not parse")
	}

	rec := &sink.Recorder{}
	ps := &podLogSink{ctx: context.Background(), base: rec, dir: "/var/log/pods",
		attrs: func(_ context.Context, uid, ns, name string) map[string]string {
			return map[string]string{"k8s.pod.uid": uid, "k8s.pod.name": name, "k8s.namespace.name": ns}
		}}
	ps.Log("INFO", "2026-10-29T10:00:00Z stdout F ERROR disk full", map[string]string{"log.file.path": "/var/log/pods/shop_web-1_abc-123/app/0.log"}, time.Now())
	l := rec.Snapshot()[0]
	if l.Sev != "ERROR" || l.Body != "ERROR disk full" || l.Attrs["resource.k8s.pod.uid"] != "abc-123" ||
		l.Attrs["resource.k8s.container.name"] != "app" || l.Attrs["log.iostream"] != "stdout" {
		t.Fatalf("pod log record: %+v", l)
	}
}
