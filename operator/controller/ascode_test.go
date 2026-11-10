package controller

import (
	"context"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/ascode/ascodetest"
	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
)

type asStore struct {
	items    []v1.AsCodeResource
	statuses map[string]v1.AsCodeStatus
}

func (s *asStore) List(context.Context) ([]v1.AsCodeResource, error) { return s.items, nil }

func (s *asStore) UpdateStatus(_ context.Context, r v1.AsCodeResource, st v1.AsCodeStatus) error {
	s.statuses[r.Name] = st
	for i := range s.items {
		if s.items[i].Name == r.Name {
			s.items[i].Status = st
		}
	}
	return nil
}

func asRig(t *testing.T, key string) (*AsCodeReconciler, *asStore, *ascodetest.Server) {
	t.Helper()
	srv := ascodetest.New(t)
	c, err := ascode.New(srv.URL, key, ascodetest.Project, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := &asStore{statuses: map[string]v1.AsCodeStatus{}, items: []v1.AsCodeResource{{
		Kind: v1.AsCodeKinds[0], Name: "checkout-errors", Namespace: "ns",
		Spec: map[string]any{"type": "metric", "query": "sum(rate(errors[5m]))"}}}}
	r := NewAsCodeReconciler(st, c)
	now := time.Unix(1_000_000, 0)
	r.Now = func() time.Time { return now }
	return r, st, srv
}

func TestAsCodeAppliesCRAndReportsReady(t *testing.T) {
	r, st, srv := asRig(t, "test-key")
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.Count("Monitor") != 1 {
		t.Fatalf("monitors = %d, want 1", srv.Count("Monitor"))
	}
	if c := st.statuses["checkout-errors"].Conditions; len(c) != 1 || c[0].Status != "True" {
		t.Fatalf("conditions = %+v", c)
	}
	n := len(srv.Calls)
	if err := r.Reconcile(context.Background()); err != nil || len(srv.Calls) != n {
		t.Fatalf("an unchanged CR inside the drift window must not call the API (calls %d -> %d, err %v)", n, len(srv.Calls), err)
	}
}

func TestAsCodeReportsAPIErrorInCondition(t *testing.T) {
	r, st, _ := asRig(t, "wrong-key")
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("want the API error returned")
	}
	c := st.statuses["checkout-errors"].Conditions
	if len(c) != 1 || c[0].Status != "False" || c[0].Reason != "ApplyFailed" || c[0].Message == "" {
		t.Fatalf("conditions = %+v", c)
	}
}
