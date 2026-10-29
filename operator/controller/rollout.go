package controller

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// rolloutOrder is R5: the services that matter most for correctness go first; anything else
// the chart deploys ("rest") follows in name order.
var rolloutOrder = []string{"api", "worker", "gateway", "edge", "alerts", "notifier", "uptime"}

func rank(svc string) int {
	if i := slices.Index(rolloutOrder, svc); i >= 0 {
		return i
	}
	return len(rolloutOrder)
}

// rollout moves the cluster to spec.version: preflight, migrate, then one Deployment at a time,
// each waited on before the next. On any failure it stops, sets Degraded and leaves the other
// Deployments (still on the previous ReplicaSet) serving; the schema is not rolled back.
func (r *Reconciler) rollout(ctx context.Context, cr *v1.WatchtowerCluster) error {
	fail := func(reason string, err error) error {
		slog.Error("rollout stopped", "step", reason, "error", err)
		r.setStatus(ctx, cr, v1.PhaseDegraded, reason, err.Error())
		return err
	}
	r.setStatus(ctx, cr, v1.PhaseMigrating, "Preflight", "running preflight checks")
	if err := r.preflight(ctx, cr); err != nil {
		return fail("PreflightFailed", err)
	}
	r.setStatus(ctx, cr, v1.PhaseMigrating, "Migrating", "running schema migrations")
	if err := r.migrate(ctx, cr); err != nil {
		return fail("MigrateFailed", err)
	}
	ds, err := r.deployments(ctx, cr)
	if err != nil {
		return fail("ListFailed", err)
	}
	sort.SliceStable(ds, func(i, j int) bool {
		ri, rj := rank(service(&ds[i])), rank(service(&ds[j]))
		if ri != rj {
			return ri < rj
		}
		return ds[i].Name < ds[j].Name
	})
	cr.Status.Services = map[string]int{}
	for i := range ds {
		r.setStatus(ctx, cr, v1.PhaseRollingOut, "RollingOut", "rolling out "+ds[i].Name)
		if err := r.rolloutOne(ctx, cr, &ds[i]); err != nil {
			return fail("RolloutFailed", fmt.Errorf("%s: %w", ds[i].Name, err))
		}
	}
	cr.Status.ObservedVersion = cr.Spec.Version
	r.setStatus(ctx, cr, v1.PhaseReady, "Ready", "all services at "+cr.Spec.Version)
	return nil
}

func (r *Reconciler) rolloutOne(ctx context.Context, cr *v1.WatchtowerCluster, d *appsv1.Deployment) error {
	apply(cr, d)
	if _, err := r.KC.AppsV1().Deployments(d.Namespace).Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	want := int32(1)
	if d.Spec.Replicas != nil {
		want = *d.Spec.Replicas
	}
	deadline := r.Now().Add(r.StepTimeout)
	for {
		cur, err := r.KC.AppsV1().Deployments(d.Namespace).Get(ctx, d.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get: %w", err)
		}
		if cur.Status.ObservedGeneration >= cur.Generation && cur.Status.UpdatedReplicas >= want && cur.Status.AvailableReplicas >= want {
			cr.Status.Services[service(d)] = int(cur.Status.ReadyReplicas)
			return nil
		}
		if err := r.sleep(ctx, deadline, "deployment "+d.Name); err != nil {
			return err
		}
	}
}
