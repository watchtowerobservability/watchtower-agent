package k8s

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestManifestIsTrimmedYAMLWithoutStatus(t *testing.T) {
	dep := fixtureObjects()[0].(*appsv1.Deployment)
	trimmed, err := Trim(dep)
	if err != nil {
		t.Fatal(err)
	}
	y := Manifest(trimmed)
	for _, want := range []string{"image: shop/web:1.2", "name: web", "replicas: 3"} {
		if !strings.Contains(y, want) {
			t.Fatalf("manifest lacks %q:\n%s", want, y)
		}
	}
	for _, never := range []string{"hunter2", "DB_PASSWORD", "status:", "resourceVersion", "availableReplicas"} {
		if strings.Contains(y, never) {
			t.Fatalf("manifest must not carry %q:\n%s", never, y)
		}
	}
	if Manifest(trimmed) != y {
		t.Fatal("manifest must be deterministic")
	}
}

func TestSpecChangeCarriesBothManifests(t *testing.T) {
	_, rec, cs := start(t, fixtureObjects()...)
	time.Sleep(200 * time.Millisecond)
	dep, err := cs.AppsV1().Deployments("shop").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dep.Spec.Template.Spec.Containers[0].Image = "shop/web:1.3"
	if _, err := cs.AppsV1().Deployments("shop").Update(context.Background(), dep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	var s sink.Sample
	eventually(t, "change record", func() bool {
		for _, x := range rec.Snapshot() {
			if x.Attrs["k8s.object.kind"] == "deployment" {
				s = x
				return true
			}
		}
		return false
	})
	if !strings.Contains(s.Attrs["k8s.object.manifest"], "image: shop/web:1.3") ||
		!strings.Contains(s.Attrs["k8s.object.manifest.previous"], "image: shop/web:1.2") {
		t.Fatalf("manifests: %v", s.Attrs)
	}
}

func TestPodSpecIsRecordedOnce(t *testing.T) {
	_, rec, cs := start(t, fixtureObjects()...)
	var s sink.Sample
	eventually(t, "pod spec record", func() bool {
		for _, x := range rec.Snapshot() {
			if x.Attrs["k8s.object.kind"] == "pod" {
				s = x
				return true
			}
		}
		return false
	})
	if s.Attrs["resource.k8s.pod.uid"] != "pod-1" || s.Attrs["k8s.object.change.fields"] != "created" ||
		!strings.Contains(s.Attrs["k8s.object.manifest"], "nodeName: node1") {
		t.Fatalf("pod record: %v", s.Attrs)
	}
	pod, err := cs.CoreV1().Pods("shop").Get(context.Background(), "web-7d9f8-abcde", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Labels = map[string]string{"touched": "yes"} // no spec fact changes
	if _, err := cs.CoreV1().Pods("shop").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	n := 0
	for _, x := range rec.Snapshot() {
		if x.Attrs["k8s.object.kind"] == "pod" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("pod spec recorded %d times, want once", n)
	}
}

func TestResourcePropsSumAndNameMissing(t *testing.T) {
	spec := &corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}}},
		{Name: "proxy", Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("64Mi")}}},
	}}
	got := ResourceProps("deployment", spec, 2)
	want := map[string]string{
		"k8s.deployment.cpu.request":    "1",
		"k8s.deployment.memory.request": "268435456",
		"k8s.deployment.limits_missing": "app,proxy",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if _, ok := got["k8s.deployment.cpu.limit"]; ok {
		t.Fatal("a limit sum with a container lacking it must be left out")
	}
	if _, ok := got["k8s.deployment.requests_missing"]; ok {
		t.Fatal("every container has requests")
	}
}

func TestStateCarriesExplorerProps(t *testing.T) {
	c, rec, _ := start(t, fixtureObjects()...)
	c.emitState(context.Background(), time.Now())
	n := find(rec, "k8s.node.condition_ready")
	if n.Attrs["resource.k8s.node.condition.Ready"] != "True" || n.Attrs["resource.k8s.node.condition.DiskPressure"] != "False" ||
		n.Attrs["resource.k8s.node.allocatable_cpu"] != "4" || n.Attrs["resource.k8s.node.allocatable_memory"] != "8589934592" {
		t.Fatalf("node props: %v", n.Attrs)
	}
	d := find(rec, "k8s.deployment.desired")
	if d.Attrs["resource.k8s.deployment.cpu.request"] != "0.30000000000000004" && d.Attrs["resource.k8s.deployment.cpu.request"] != "0.3" {
		t.Fatalf("deployment request = 3 x 100m: %v", d.Attrs)
	}
	if d.Attrs["resource.k8s.deployment.limits_missing"] != "app" {
		t.Fatalf("the cpu limit is missing: %v", d.Attrs)
	}
}

func TestKubeletUsageNamesPodAndWorkloadAsPointAttrs(t *testing.T) {
	s := &Summary{Pods: []PodStats{{PodRef: PodRef{Name: "web-1", Namespace: "shop", UID: "u1"},
		CPU: &CPUStats{UsageNanoCores: ptr(uint64(5e8))}}}}
	rec := &sink.Recorder{}
	Emit(rec, s, map[string]string{"k8s.node.name": "n1"}, func(r PodRef) map[string]string {
		return map[string]string{"k8s.pod.uid": r.UID, "k8s.parent.id": "dep-1"}
	}, time.Now())
	p := find(rec, "k8s.pod.cpu.usage")
	if p == nil || p.Attrs["k8s.pod.uid"] != "u1" || p.Attrs["k8s.parent.id"] != "dep-1" || p.Attrs["resource.k8s.pod.uid"] != "u1" {
		t.Fatalf("pod usage attrs: %+v", p)
	}
	if _, ok := p.Attrs["resource.k8s.parent.id"]; ok {
		t.Fatal("the node agent must not name a parent on the resource")
	}
}
