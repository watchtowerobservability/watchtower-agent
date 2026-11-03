package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// A missing grant says what to do, and never names the secret.
func TestK8sRefForbiddenIsClear(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "db-cred", errors.New("no"))
	})
	r := &secretResolver{kube: func() (kubernetes.Interface, error) { return cs, nil }}
	_, err := r.k8s(context.Background(), "mon/db-cred#k")
	if err == nil || !strings.Contains(err.Error(), "rbac.secretRefs") || strings.Contains(err.Error(), "db-cred") {
		t.Fatalf("%v", err)
	}
}
