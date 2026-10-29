package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

type agentMem struct{ cr v1.WatchtowerAgent }

func (m *agentMem) Get(context.Context) (*v1.WatchtowerAgent, error) { c := m.cr; return &c, nil }
func (m *agentMem) UpdateStatus(_ context.Context, st v1.AgentStatus) error {
	m.cr.Status = st
	return nil
}

func TestAgentReconcileRollsImageAndReportsStatus(t *testing.T) {
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "wta", Namespace: "wt"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "agent", Image: "reg/wt-agent:1.0.0"}}}}},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3, UpdatedNumberScheduled: 3}}
	kc := fake.NewSimpleClientset(ds)
	st := &agentMem{cr: v1.WatchtowerAgent{Name: "wta", Namespace: "wt", Spec: v1.AgentSpec{Version: "1.1.0"}}}
	r := &AgentReconciler{KC: kc, Store: st, Namespace: "wt"}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := kc.AppsV1().DaemonSets("wt").Get(context.Background(), "wta", metav1.GetOptions{})
	if img := got.Spec.Template.Spec.Containers[0].Image; img != "reg/wt-agent:1.1.0" {
		t.Fatalf("image %s", img)
	}
	if st.cr.Status.Desired != 3 || st.cr.Status.Ready != 3 {
		t.Fatalf("status %+v", st.cr.Status)
	}
	// A paused CR is left alone.
	st.cr.Spec.Paused, st.cr.Spec.Version = true, "9.9.9"
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = kc.AppsV1().DaemonSets("wt").Get(context.Background(), "wta", metav1.GetOptions{})
	if strings.Contains(got.Spec.Template.Spec.Containers[0].Image, "9.9.9") {
		t.Fatal("paused agent was rolled")
	}
}

func review(t *testing.T, pod corev1.Pod) admissionv1.AdmissionReview {
	t.Helper()
	raw, _ := json.Marshal(pod)
	in := admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{UID: "u1",
		Kind: metav1.GroupVersionKind{Kind: "Pod"}, Object: runtime.RawExtension{Raw: raw}}}
	b, _ := json.Marshal(in)
	rec := httptest.NewRecorder()
	Mutate(4318).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(b)))
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMutateInjectsEndpointAndOptsOut(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	out := review(t, pod)
	if out.Response == nil || !out.Response.Allowed || out.Response.UID != "u1" {
		t.Fatalf("response %+v", out.Response)
	}
	p := string(out.Response.Patch)
	if !strings.Contains(p, "WT_NODE_IP") || !strings.Contains(p, "OTEL_EXPORTER_OTLP_ENDPOINT") || !strings.Contains(p, "http://$(WT_NODE_IP):4318") {
		t.Fatalf("patch %s", p)
	}
	pod.Annotations = map[string]string{v1.InjectAnnotation: "false"}
	if out := review(t, pod); len(out.Response.Patch) != 0 {
		t.Fatalf("opted-out pod patched: %s", out.Response.Patch)
	}
}

func TestMutateBadBodyIs400(t *testing.T) {
	rec := httptest.NewRecorder()
	Mutate(4318).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
}
