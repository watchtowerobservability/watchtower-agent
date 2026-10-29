package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

type memStore struct {
	mu sync.Mutex
	cr v1.WatchtowerCluster
}

func (m *memStore) Get(context.Context) (*v1.WatchtowerCluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cr
	return &c, nil
}

func (m *memStore) UpdateStatus(_ context.Context, st v1.Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cr.Status = st
	return nil
}

type rig struct {
	r                *Reconciler
	kc               *fake.Clientset
	store            *memStore
	events           []string // "job:<kind>" and "dep:<service>" in call order
	failJob, failDep string
	now              time.Time
}

func dep(svc string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "wt-" + svc, Namespace: "ns", Labels: map[string]string{
			"app.kubernetes.io/instance": "wt", "app.kubernetes.io/component": svc}},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: svc, Image: "reg/wt:1.0"}}}}},
	}
}

func newRig(t *testing.T, version string) *rig {
	t.Helper()
	g := &rig{now: time.Unix(1_000_000, 0)}
	objs := []runtime.Object{}
	for _, s := range []string{"web", "uptime", "notifier", "alerts", "edge", "gateway", "worker", "api"} {
		objs = append(objs, dep(s, 2))
	}
	g.kc = fake.NewSimpleClientset(objs...)
	g.kc.PrependReactor("create", "jobs", func(a k8stesting.Action) (bool, runtime.Object, error) {
		j := a.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		kind := j.Labels["app.kubernetes.io/component"]
		g.events = append(g.events, "job:"+kind)
		if kind == g.failJob {
			j.Status.Failed = 1
		} else {
			j.Status.Succeeded = 1
		}
		return false, nil, nil
	})
	g.kc.PrependReactor("update", "deployments", func(a k8stesting.Action) (bool, runtime.Object, error) {
		d := a.(k8stesting.UpdateAction).GetObject().(*appsv1.Deployment)
		svc := service(d)
		if strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Image, "reg/wt:") && !strings.HasSuffix(d.Spec.Template.Spec.Containers[0].Image, ":1.0") {
			g.events = append(g.events, "dep:"+svc)
		}
		if svc != g.failDep && d.Spec.Replicas != nil {
			d.Status.UpdatedReplicas, d.Status.AvailableReplicas, d.Status.ReadyReplicas = *d.Spec.Replicas, *d.Spec.Replicas, *d.Spec.Replicas
		}
		return false, nil, nil
	})
	g.store = &memStore{cr: v1.WatchtowerCluster{Name: "wt", Namespace: "ns",
		Spec:   v1.Spec{Version: version},
		Status: v1.Status{ObservedVersion: "1.0", Phase: v1.PhaseReady}}}
	g.r = NewReconciler(g.kc, g.store, func(context.Context) (int64, error) { return 0, nil })
	g.r.Now = func() time.Time { // advances, so wait loops time out
		g.now = g.now.Add(time.Millisecond)
		return g.now
	}
	g.r.Poll, g.r.StepTimeout = time.Millisecond, 20*time.Millisecond
	return g
}

func (g *rig) deploy(t *testing.T, svc string) *appsv1.Deployment {
	t.Helper()
	d, err := g.kc.AppsV1().Deployments("ns").Get(context.Background(), "wt-"+svc, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRolloutOrder(t *testing.T) {
	g := newRig(t, "2.0")
	if err := g.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"job:preflight", "job:migrate", "dep:api", "dep:worker", "dep:gateway", "dep:edge", "dep:alerts", "dep:notifier", "dep:uptime", "dep:web"}
	if !reflect.DeepEqual(g.events, want) {
		t.Fatalf("order\n got %v\nwant %v", g.events, want)
	}
	st := g.store.cr.Status
	if st.Phase != v1.PhaseReady || st.ObservedVersion != "2.0" || st.Services["api"] != 2 {
		t.Fatalf("status %+v", st)
	}
}

func TestStopsAtFailedStepAndMarksDegraded(t *testing.T) {
	g := newRig(t, "2.0")
	g.failDep = "gateway"
	if err := g.r.Reconcile(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if g.store.cr.Status.Phase != v1.PhaseDegraded || g.store.cr.Status.ObservedVersion != "1.0" {
		t.Fatalf("status %+v", g.store.cr.Status)
	}
	for _, later := range []string{"edge", "alerts", "notifier", "uptime", "web"} {
		if img := g.deploy(t, later).Spec.Template.Spec.Containers[0].Image; img != "reg/wt:1.0" {
			t.Fatalf("%s was rolled out after the failure: %s", later, img)
		}
	}
}

func TestMigrateJobCompletesBeforeApiRollout(t *testing.T) {
	g := newRig(t, "2.0")
	g.failJob = "migrate"
	if err := g.r.Reconcile(context.Background()); err == nil {
		t.Fatal("want error")
	}
	for _, e := range g.events {
		if strings.HasPrefix(e, "dep:") {
			t.Fatalf("deployment rolled out despite failed migrate: %v", g.events)
		}
	}
	if g.store.cr.Status.Phase != v1.PhaseDegraded {
		t.Fatalf("phase %s", g.store.cr.Status.Phase)
	}
}

func TestPreflightFailureBlocksUpgrade(t *testing.T) {
	g := newRig(t, "2.0")
	g.failJob = "preflight"
	if err := g.r.Reconcile(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if !reflect.DeepEqual(g.events, []string{"job:preflight"}) {
		t.Fatalf("events %v", g.events)
	}
	if g.store.cr.Status.Conditions[0].Reason != "PreflightFailed" {
		t.Fatalf("conditions %+v", g.store.cr.Status.Conditions)
	}
}

func TestWorkerScaleUpImmediateScaleDownOneStep(t *testing.T) {
	g := newRig(t, "1.0")
	g.store.cr.Spec.WorkerScaling = &v1.WorkerScaling{Min: 1, Max: 10, LagPerReplica: 100}
	g.r.DriftEvery = 24 * time.Hour
	lag := int64(750)
	g.r.Lag = func(context.Context) (int64, error) { return lag, nil }
	ctx := context.Background()
	if err := g.r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := *g.deploy(t, "worker").Spec.Replicas; n != 8 {
		t.Fatalf("scale up: %d, want 8", n)
	}
	// within 60 s nothing is re-evaluated
	g.now = g.now.Add(30 * time.Second)
	lag = 0
	_ = g.r.Reconcile(ctx)
	if n := *g.deploy(t, "worker").Spec.Replicas; n != 8 {
		t.Fatalf("evaluated too early: %d", n)
	}
	g.now = g.now.Add(31 * time.Second)
	_ = g.r.Reconcile(ctx)
	if n := *g.deploy(t, "worker").Spec.Replicas; n != 7 {
		t.Fatalf("scale down one step: %d, want 7", n)
	}
	g.now = g.now.Add(61 * time.Second) // evaluated again, but the 5 min down limit holds
	_ = g.r.Reconcile(ctx)
	if n := *g.deploy(t, "worker").Spec.Replicas; n != 7 {
		t.Fatalf("down limit ignored: %d", n)
	}
	g.now = g.now.Add(5 * time.Minute)
	_ = g.r.Reconcile(ctx)
	if n := *g.deploy(t, "worker").Spec.Replicas; n != 6 {
		t.Fatalf("second step: %d, want 6", n)
	}
}

func TestTargetClamps(t *testing.T) {
	ws := &v1.WorkerScaling{Min: 2, Max: 5, LagPerReplica: 100}
	for lag, want := range map[int64]int{0: 2, 150: 2, 301: 4, 10_000: 5} {
		if got := target(ws, lag); got != want {
			t.Errorf("lag %d: %d, want %d", lag, got, want)
		}
	}
}

func TestPausedDoesNothing(t *testing.T) {
	g := newRig(t, "2.0")
	g.store.cr.Spec.Paused = true
	g.kc.ClearActions()
	if err := g.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := g.kc.Actions(); len(a) != 0 || len(g.events) != 0 {
		t.Fatalf("paused cluster touched the API: %v", a)
	}
}

func TestDriftRepaired(t *testing.T) {
	g := newRig(t, "1.0")
	g.store.cr.Spec.Replicas = map[string]int{"api": 3}
	// someone edits the Deployment by hand
	d := g.deploy(t, "api")
	one := int32(1)
	d.Spec.Replicas = &one
	d.Spec.Template.Spec.Containers[0].Image = "reg/wt:hotfix"
	if _, err := g.kc.AppsV1().Deployments("ns").Update(context.Background(), d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := g.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := g.deploy(t, "api")
	if *got.Spec.Replicas != 3 || got.Spec.Template.Spec.Containers[0].Image != "reg/wt:1.0" {
		t.Fatalf("not repaired: %d %s", *got.Spec.Replicas, got.Spec.Template.Spec.Containers[0].Image)
	}
}

func TestWithTag(t *testing.T) {
	for in, want := range map[string]string{
		"reg:5000/wt:1.0": "reg:5000/wt:2", "reg/wt": "reg/wt:2", "reg/wt@sha256:ab": "reg/wt:2",
	} {
		if got := withTag(in, "2"); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestLagErrorDoesNotFailReconcile(t *testing.T) {
	g := newRig(t, "1.0")
	g.store.cr.Spec.WorkerScaling = &v1.WorkerScaling{Min: 1, Max: 4, LagPerReplica: 10}
	g.r.Lag = func(context.Context) (int64, error) { return 0, errors.New("down") }
	if err := g.r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}
