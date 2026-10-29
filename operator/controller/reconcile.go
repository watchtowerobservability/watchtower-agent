// Package controller reconciles a WatchtowerCluster: ordered rollouts, lag-based worker scaling
// and drift repair of the Deployments the Helm chart created.
package controller

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// Store reads the custom resource and writes its status subresource.
type Store interface {
	Get(ctx context.Context) (*v1.WatchtowerCluster, error)
	UpdateStatus(ctx context.Context, st v1.Status) error
}

// Reconciler owns the Deployments labelled app.kubernetes.io/instance=<cluster name>.
type Reconciler struct {
	KC    kubernetes.Interface
	Store Store
	// Lag returns the summed consumer lag (wt-api /internal/lag).
	Lag func(ctx context.Context) (int64, error)
	Now func() time.Time
	// Poll is the wait-loop interval; StepTimeout bounds each Job or Deployment wait.
	Poll, StepTimeout time.Duration
	// DriftEvery is how often hand edits are reverted (5 min).
	DriftEvery time.Duration

	mu        sync.Mutex
	lastDrift time.Time
	scale     scaleState
}

// NewReconciler returns a Reconciler with the production timings.
func NewReconciler(kc kubernetes.Interface, st Store, lag func(context.Context) (int64, error)) *Reconciler {
	return &Reconciler{KC: kc, Store: st, Lag: lag, Now: time.Now,
		Poll: 3 * time.Second, StepTimeout: 10 * time.Minute, DriftEvery: 5 * time.Minute}
}

// Reconcile runs one pass: roll out a new version, otherwise repair drift and scale workers.
// A paused cluster is left alone. A failed rollout leaves the phase Degraded.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	cr, err := r.Store.Get(ctx)
	if err != nil {
		return fmt.Errorf("get cluster: %w", err)
	}
	if cr.Spec.Paused || cr.Spec.Version == "" {
		return nil
	}
	if cr.Status.ObservedVersion != cr.Spec.Version {
		return r.rollout(ctx, cr)
	}
	r.mu.Lock()
	due := r.lastDrift.IsZero() || r.Now().Sub(r.lastDrift) >= r.DriftEvery
	if due {
		r.lastDrift = r.Now()
	}
	r.mu.Unlock()
	if due {
		if err := r.repairDrift(ctx, cr); err != nil {
			return err
		}
	}
	if !cr.Spec.Maintenance {
		if err := r.scaleWorkers(ctx, cr); err != nil {
			slog.Warn("worker scaling skipped", "error", err)
		}
	}
	return nil
}

func (r *Reconciler) deployments(ctx context.Context, cr *v1.WatchtowerCluster) ([]appsv1.Deployment, error) {
	l, err := r.KC.AppsV1().Deployments(cr.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/instance=" + cr.Name})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	return l.Items, nil
}

func service(d *appsv1.Deployment) string { return d.Labels["app.kubernetes.io/component"] }

// withTag replaces the tag of an image reference (a digest is dropped).
func withTag(image, tag string) string {
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndexByte(image, ':'); i > strings.LastIndexByte(image, '/') {
		image = image[:i]
	}
	return image + ":" + tag
}

// apply sets the spec's image tag and replica count on d in place; it reports a change. The
// worker's count is only forced when spec.replicas names it, otherwise the scaler owns it.
func apply(cr *v1.WatchtowerCluster, d *appsv1.Deployment) bool {
	changed := false
	for i := range d.Spec.Template.Spec.Containers {
		c := &d.Spec.Template.Spec.Containers[i]
		if img := withTag(c.Image, cr.Spec.Version); img != c.Image {
			c.Image, changed = img, true
		}
	}
	if n, ok := cr.Spec.Replicas[service(d)]; ok {
		if d.Spec.Replicas == nil || int(*d.Spec.Replicas) != n {
			want := int32(min(max(n, 0), 1000)) //nolint:gosec // clamped
			d.Spec.Replicas, changed = &want, true
		}
	}
	return changed
}

func (r *Reconciler) repairDrift(ctx context.Context, cr *v1.WatchtowerCluster) error {
	ds, err := r.deployments(ctx, cr)
	if err != nil {
		return err
	}
	for i := range ds {
		d := &ds[i]
		if !apply(cr, d) {
			continue
		}
		slog.Info("repairing drift", "deployment", d.Name)
		if _, err := r.KC.AppsV1().Deployments(d.Namespace).Update(ctx, d, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("repair %s: %w", d.Name, err)
		}
	}
	return nil
}

func (r *Reconciler) setStatus(ctx context.Context, cr *v1.WatchtowerCluster, ph v1.Phase, reason, msg string) {
	cr.Status.Phase = ph
	ok := "False"
	if ph == v1.PhaseReady {
		ok = "True"
	}
	cr.Status.Conditions = []v1.Condition{{Type: "Ready", Status: ok, Reason: reason, Message: msg,
		LastTransitionTime: r.Now().UTC().Format(time.RFC3339)}}
	if err := r.Store.UpdateStatus(ctx, cr.Status); err != nil {
		slog.Warn("status update failed", "error", err)
	}
}
