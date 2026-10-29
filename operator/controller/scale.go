package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

const (
	scaleEvery     = 60 * time.Second // lag is evaluated at most this often
	scaleDownEvery = 5 * time.Minute  // and the count falls by one step at most this often
)

type scaleState struct{ evaluated, down time.Time }

// target is clamp(ceil(lag / lagPerReplica), min, max).
func target(ws *v1.WorkerScaling, lag int64) int {
	n := ws.Min
	if ws.LagPerReplica > 0 && lag > 0 {
		n = int((lag + ws.LagPerReplica - 1) / ws.LagPerReplica)
	}
	return min(max(n, ws.Min), max(ws.Max, ws.Min))
}

// scaleWorkers sets the worker Deployment's replicas from the consumer lag: scale-up jumps
// straight to the target, scale-down moves one step per five minutes. A worker count pinned in
// spec.replicas wins over the scaler.
func (r *Reconciler) scaleWorkers(ctx context.Context, cr *v1.WatchtowerCluster) error {
	ws := cr.Spec.WorkerScaling
	if _, pinned := cr.Spec.Replicas["worker"]; ws == nil || pinned || r.Lag == nil {
		return nil
	}
	r.mu.Lock()
	now := r.Now()
	if !r.scale.evaluated.IsZero() && now.Sub(r.scale.evaluated) < scaleEvery {
		r.mu.Unlock()
		return nil
	}
	r.scale.evaluated = now
	r.mu.Unlock()

	lag, err := r.Lag(ctx)
	if err != nil {
		return fmt.Errorf("read lag: %w", err)
	}
	ds, err := r.deployments(ctx, cr)
	if err != nil {
		return err
	}
	for i := range ds {
		d := &ds[i]
		if service(d) != "worker" {
			continue
		}
		if d.Spec.Replicas == nil {
			return errors.New("worker Deployment has no replica count")
		}
		cur, want := int(*d.Spec.Replicas), target(ws, lag)
		switch {
		case want > cur:
		case want < cur:
			r.mu.Lock()
			ok := r.scale.down.IsZero() || now.Sub(r.scale.down) >= scaleDownEvery
			if ok {
				r.scale.down = now
			}
			r.mu.Unlock()
			if !ok {
				return nil
			}
			want = cur - 1
		default:
			return nil
		}
		n := int32(want) //nolint:gosec // clamped by target
		d.Spec.Replicas = &n
		slog.Info("scaling workers", "from", cur, "to", want, "lag", lag)
		if _, err := r.KC.AppsV1().Deployments(d.Namespace).Update(ctx, d, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("scale %s: %w", d.Name, err)
		}
	}
	return nil
}
