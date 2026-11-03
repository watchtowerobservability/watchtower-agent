package k8s

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func ctrReq(name, cpu, mem string) corev1.Container {
	return corev1.Container{Name: name, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
		corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem)}}}
}

func TestRightsizerStrategiesBoundsAndAudit(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	objs := map[string]*workloadObj{
		"shop/cart": {Kind: "deployment", Namespace: "shop", Name: "cart", Annotations: map[string]string{AnnRightsize: "TriggerRollout"},
			Containers: []corev1.Container{ctrReq("app", "1", "2Gi"), ctrReq("sidecar", "100m", "128Mi")}},
		"shop/web":  {Kind: "deployment", Namespace: "shop", Name: "web", Annotations: map[string]string{AnnRightsize: "Auto"}, Containers: []corev1.Container{ctrReq("app", "1", "1Gi")}},
		"shop/db":   {Kind: "statefulset", Namespace: "shop", Name: "db", Containers: []corev1.Container{ctrReq("pg", "2", "4Gi")}},
		"shop/cool": {Kind: "deployment", Namespace: "shop", Name: "cool", Annotations: map[string]string{AnnRightsize: "TriggerRollout", annRightsizeAt: now.Add(-time.Hour).Format(time.RFC3339)}, Containers: []corev1.Container{ctrReq("app", "1", "1Gi")}},
	}
	recs := []Recommendation{
		{Cluster: "prod", Namespace: "shop", Workload: "cart", Confidence: "high", Current: Res{1.1, 2.125}, Recommended: Res{0.2, 1}},
		{Cluster: "prod", Namespace: "shop", Workload: "web", Confidence: "high", Current: Res{1, 1}, Recommended: Res{0.5, 0.5}},
		{Cluster: "prod", Namespace: "shop", Workload: "StatefulSet/db", Confidence: "high", Current: Res{2, 4}, Recommended: Res{1, 2}},
		{Cluster: "prod", Namespace: "shop", Workload: "cool", Confidence: "high", Current: Res{1, 1}, Recommended: Res{0.5, 0.5}},
		{Cluster: "other", Namespace: "shop", Workload: "cart", Confidence: "high", Current: Res{1, 1}, Recommended: Res{0.1, 0.1}},
	}
	var patched []string
	var events int
	rec := &sink.Recorder{}
	r := &Rightsizer{Cfg: RightsizeConfig{Cluster: "prod"}, Now: func() time.Time { return now }, Out: rec,
		Fetch: func(context.Context) ([]Recommendation, error) { return recs, nil },
		Get:   func(_ context.Context, _, ns, name string) (*workloadObj, error) { return objs[ns+"/"+name], nil },
		Patch: func(_ context.Context, kind, _, name string, _ []byte) error {
			patched = append(patched, kind+"/"+name)
			return nil
		},
		Event: func(context.Context, *workloadObj, string) { events++ },
	}
	ds, err := r.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 4 || len(patched) != 1 || patched[0] != "deployment/cart" || events != 1 || len(rec.Snapshot()) != 1 {
		t.Fatalf("decisions %+v patched %v events %d", ds, patched, events)
	}
	if ds[1].Action != "waiting for the owner's next rollout" || ds[2].Action != "disabled" || ds[3].Action != "skipped: cooldown" {
		t.Fatalf("actions: %+v", ds)
	}
	var p struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name      string `json:"name"`
						Resources struct {
							Requests map[string]string `json:"requests"`
						} `json:"resources"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(ds[0].Patch, &p); err != nil {
		t.Fatal(err)
	}
	cs := p.Spec.Template.Spec.Containers
	// 0.2 / 1.1 cores is bounded to halving per step: 1 core -> 500m, 100m -> 50m; memory 1 / 2.125 GiB -> x0.5 bound too.
	if len(cs) != 2 || cs[0].Resources.Requests["cpu"] != "500m" || cs[1].Resources.Requests["cpu"] != "50m" || cs[0].Resources.Requests["memory"] != "1Gi" || cs[1].Resources.Requests["memory"] != "64Mi" {
		t.Fatalf("patch: %s", ds[0].Patch)
	}
	objs["shop/web"].RollingOut = true
	patched = nil
	r.Cfg.DryRun = true
	if _, err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(patched) != 0 {
		t.Fatalf("dry run patched %v", patched)
	}
}
