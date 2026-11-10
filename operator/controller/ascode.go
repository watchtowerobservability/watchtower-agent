package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

// AsCodeStore lists the monitor, SLO and dashboard CRs and writes their status.
type AsCodeStore interface {
	List(ctx context.Context) ([]v1.AsCodeResource, error)
	UpdateStatus(ctx context.Context, r v1.AsCodeResource, st v1.AsCodeStatus) error
}

// AsCodeReconciler applies each CR through the same engine as `wtctl apply` (internal/ascode),
// so the API sees the managed-by label and locks the object against UI edits. A CR is re-applied
// when its spec changes and every DriftEvery to repair edits made elsewhere.
// shortcut: deleting a CR does not delete the API object (no finalizer), run `wtctl apply --prune`
// or delete it in the UI; add a finalizer when in-cluster deletes must propagate.
type AsCodeReconciler struct {
	Store      AsCodeStore
	Client     *ascode.Client
	Now        func() time.Time
	DriftEvery time.Duration

	lastSync map[string]time.Time
}

// NewAsCodeReconciler returns a reconciler with the production timings.
func NewAsCodeReconciler(st AsCodeStore, c *ascode.Client) *AsCodeReconciler {
	c.ManagedBy = "operator"
	return &AsCodeReconciler{Store: st, Client: c, Now: time.Now, DriftEvery: 5 * time.Minute}
}

// Reconcile runs one pass over every as-code CR; one failing CR does not stop the others.
func (r *AsCodeReconciler) Reconcile(ctx context.Context) error {
	items, err := r.Store.List(ctx)
	if err != nil {
		return fmt.Errorf("list as-code resources: %w", err)
	}
	if r.lastSync == nil {
		r.lastSync = map[string]time.Time{}
	}
	var errs []string
	for _, it := range items {
		key := it.Kind.Kind + "/" + it.Namespace + "/" + it.Name
		h := specHash(it.Spec)
		ready := len(it.Status.Conditions) > 0 && it.Status.Conditions[0].Status == "True"
		last, seen := r.lastSync[key]
		if ready && it.Status.ObservedHash == h && seen && r.Now().Sub(last) < r.DriftEvery {
			continue
		}
		r.lastSync[key] = r.Now()
		cond := v1.Condition{Type: "Ready", Status: "True", Reason: "Applied", LastTransitionTime: r.Now().UTC().Format(time.RFC3339)}
		if err := r.apply(ctx, it); err != nil {
			cond.Status, cond.Reason, cond.Message = "False", "ApplyFailed", err.Error()
			errs = append(errs, key+": "+err.Error())
		}
		if err := r.Store.UpdateStatus(ctx, it, v1.AsCodeStatus{ObservedHash: h, Conditions: []v1.Condition{cond}}); err != nil {
			errs = append(errs, key+": status: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (r *AsCodeReconciler) apply(ctx context.Context, it v1.AsCodeResource) error {
	doc := ascode.Doc{APIVersion: ascode.APIVersion, Kind: it.Kind.AsCode,
		Metadata: ascode.Metadata{Name: it.Name, Labels: map[string]string{ascode.ManagedByKey: "operator:" + it.Namespace}}, Spec: it.Spec}
	plan, err := r.Client.Plan(ctx, []ascode.Doc{doc}, false)
	if err != nil {
		return err
	}
	_, err = r.Client.Apply(ctx, plan, false, nil)
	return err
}

func specHash(spec map[string]any) string {
	b, _ := json.Marshal(spec) // map keys are sorted, so equal specs hash equal
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
