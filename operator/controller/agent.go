package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// AgentStore reads a WatchtowerAgent custom resource and writes its status.
type AgentStore interface {
	Get(ctx context.Context) (*v1.WatchtowerAgent, error)
	UpdateStatus(ctx context.Context, st v1.AgentStatus) error
}

// AgentReconciler rolls the node agent DaemonSet (same name as the CR, created by the
// watchtower-agent chart) to spec.version and reports ready/desired counts. It only changes the
// image tag of the `agent` container: the token Secret, endpoint and config stay with Helm.
type AgentReconciler struct {
	KC        kubernetes.Interface
	Store     AgentStore
	Namespace string
}

// Reconcile runs one pass. A paused or version-less CR is left alone.
func (r *AgentReconciler) Reconcile(ctx context.Context) error {
	cr, err := r.Store.Get(ctx)
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}
	if cr.Spec.Paused || cr.Spec.Version == "" {
		return nil
	}
	ds, err := r.KC.AppsV1().DaemonSets(r.Namespace).Get(ctx, cr.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get daemonset: %w", err)
	}
	changed := false
	for i := range ds.Spec.Template.Spec.Containers {
		c := &ds.Spec.Template.Spec.Containers[i]
		if c.Name != "agent" {
			continue
		}
		if want := withTag(c.Image, cr.Spec.Version); want != c.Image {
			c.Image, changed = want, true
		}
	}
	if changed {
		if ds, err = r.KC.AppsV1().DaemonSets(r.Namespace).Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update daemonset: %w", err)
		}
	}
	st := v1.AgentStatus{Ready: int(ds.Status.NumberReady), Desired: int(ds.Status.DesiredNumberScheduled)}
	if !changed && ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled {
		st.ObservedVersion = cr.Spec.Version
	} else {
		st.ObservedVersion = cr.Status.ObservedVersion
	}
	if st == cr.Status {
		return nil
	}
	return r.Store.UpdateStatus(ctx, st)
}
