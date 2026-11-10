package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeEdge struct {
	mu       sync.Mutex
	targets  string
	desired  string
	reports  []map[string]any
	finished map[string]bool // like the server: a done or failed target is no longer pending
}

func (f *fakeEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method == http.MethodGet {
		var all []map[string]any
		_ = json.Unmarshal([]byte(f.targets), &all)
		open := []map[string]any{}
		for _, t := range all {
			if !f.finished[t["id"].(string)] {
				open = append(open, t)
			}
		}
		b, _ := json.Marshal(open)
		_, _ = io.WriteString(w, `{"targets":`+string(b)+`,"desired":`+f.desired+`}`)
		return
	}
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.reports = append(f.reports, m)
	if st := m["status"]; st == "done" || st == "failed" {
		if f.finished == nil {
			f.finished = map[string]bool{}
		}
		f.finished[m["id"].(string)] = true
	}
	w.WriteHeader(http.StatusNoContent)
}

func injected(name, ns string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{AutoInstPrefix + "java": "true"}}}}}
}

func statuses(edge *fakeEdge) string {
	var got []string
	for _, r := range edge.reports {
		got = append(got, r["id"].(string)+":"+r["status"].(string))
	}
	return strings.Join(got, ",")
}

func TestSDKUpgradeRollsOptedInWorkloadsAndReportsDoneOnlyWhenTheRolloutIsComplete(t *testing.T) {
	t.Cleanup(func() { setAutoVersions(nil) })
	edge := &fakeEdge{
		targets: `[{"id":"t1","service":"shop","language":"java","version":"2.40.0"},{"id":"t2","service":"ghost","language":"java","version":"2.40.0"}]`,
		desired: `[{"language":"java","version":"2.40.0"}]`,
	}
	srv := httptest.NewServer(edge)
	defer srv.Close()
	shop := injected("shop", "prod")
	shop.Spec.Replicas = ptr(int32(2))
	kc := fake.NewSimpleClientset(shop, injected("other", "prod"))
	u := &SDKUpgrader{KC: kc, Client: &SDKClient{Base: srv.URL, Token: "wti_x", HTTP: srv.Client()}}
	ctx := context.Background()
	setStatus := func(st appsv1.DeploymentStatus) {
		d, _ := kc.AppsV1().Deployments("prod").Get(ctx, "shop", metav1.GetOptions{})
		d.Status = st
		if _, err := kc.AppsV1().Deployments("prod").UpdateStatus(ctx, d, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	pass := func() {
		t.Helper()
		if err := u.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	pass() // applying only
	if d, _ := kc.AppsV1().Deployments("prod").Get(ctx, "shop", metav1.GetOptions{}); d.Spec.Template.Annotations[SDKUpgradeAnnotation+"-java"] != "" {
		t.Fatal("rolled on the first pass")
	}
	setStatus(appsv1.DeploymentStatus{Replicas: 3, UpdatedReplicas: 1, AvailableReplicas: 2})
	pass() // stamps; ghost fails (no workload)
	d, _ := kc.AppsV1().Deployments("prod").Get(ctx, "shop", metav1.GetOptions{})
	if d.Spec.Template.Annotations[SDKUpgradeAnnotation+"-java"] != "2.40.0" {
		t.Fatalf("annotations %v", d.Spec.Template.Annotations)
	}
	if o, _ := kc.AppsV1().Deployments("prod").Get(ctx, "other", metav1.GetOptions{}); o.Spec.Template.Annotations[SDKUpgradeAnnotation+"-java"] != "" {
		t.Fatal("an unrelated workload was rolled")
	}
	pass() // mid-rollout: old pods still around, nothing reported
	if got := statuses(edge); got != "t1:applying,t2:applying,t2:failed" {
		t.Fatalf("reports %v", got)
	}
	setStatus(appsv1.DeploymentStatus{Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2})
	pass()
	if got := statuses(edge); got != "t1:applying,t2:applying,t2:failed,t1:done" {
		t.Fatalf("reports %v", got)
	}
	// the webhook now injects the desired tag
	if img := autoImage("java"); !strings.HasSuffix(img, ":2.40.0") || !strings.Contains(img, "autoinstrumentation-java") {
		t.Fatalf("image %q", img)
	}
	// a workload already on the version is not stamped again
	if b := u.patchFor(d.Spec.Template, "prod", "shop", nil, SDKTarget{Service: "shop", Language: "java", Version: "2.40.0"}); b != nil {
		t.Fatal("repatched a workload already on the version")
	}
}

func TestSDKUpgradeFailsWithProgressDeadlineExceeded(t *testing.T) {
	t.Cleanup(func() { setAutoVersions(nil) })
	edge := &fakeEdge{targets: `[{"id":"t1","service":"shop","language":"java","version":"2.40.0"}]`, desired: `[]`}
	srv := httptest.NewServer(edge)
	defer srv.Close()
	kc := fake.NewSimpleClientset(injected("shop", "prod"))
	u := &SDKUpgrader{KC: kc, Client: &SDKClient{Base: srv.URL, Token: "t", HTTP: srv.Client()}}
	ctx := context.Background()
	for range 2 { // applying, then stamp
		if err := u.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := kc.AppsV1().Deployments("prod").Get(ctx, "shop", metav1.GetOptions{})
	d.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
		Reason: "ProgressDeadlineExceeded", Message: "ReplicaSet shop-2 has timed out progressing."}}
	if _, err := kc.AppsV1().Deployments("prod").UpdateStatus(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := u.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	last := edge.reports[len(edge.reports)-1]
	if last["status"] != "failed" || !strings.Contains(last["error"].(string), "ProgressDeadlineExceeded") {
		t.Fatalf("last report %v", last)
	}
}

func TestSDKUpgradeTimesOutARolloutThatNeverCompletes(t *testing.T) {
	t.Cleanup(func() { setAutoVersions(nil) })
	edge := &fakeEdge{targets: `[{"id":"t1","service":"shop","language":"java","version":"2.40.0"}]`, desired: `[]`}
	srv := httptest.NewServer(edge)
	defer srv.Close()
	clock := time.Now()
	u := &SDKUpgrader{KC: fake.NewSimpleClientset(injected("shop", "prod")), Now: func() time.Time { return clock },
		Client: &SDKClient{Base: srv.URL, Token: "t", HTTP: srv.Client()}}
	for range 3 { // applying, stamp, still rolling (nothing is ready)
		if err := u.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	clock = clock.Add(rolloutTimeout + time.Minute)
	if err := u.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := edge.reports[len(edge.reports)-1]
	if last["status"] != "failed" || !strings.Contains(last["error"].(string), "did not complete") {
		t.Fatalf("last report %v", last)
	}
}

func ptr[T any](v T) *T { return &v }

func TestSDKUpgradeRejectsUnsafeVersions(t *testing.T) {
	t.Cleanup(func() { setAutoVersions(nil) })
	edge := &fakeEdge{targets: `[{"id":"t1","service":"s","language":"java","version":"../x"}]`, desired: `[{"language":"java","version":"a/b"}]`}
	srv := httptest.NewServer(edge)
	defer srv.Close()
	u := &SDKUpgrader{KC: fake.NewSimpleClientset(), Client: &SDKClient{Base: srv.URL, Token: "t", HTTP: srv.Client()}}
	if err := u.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if autoVersion("java") != "" || len(edge.reports) != 1 || edge.reports[0]["status"] != "failed" {
		t.Fatalf("version %q reports %v", autoVersion("java"), edge.reports)
	}
}
