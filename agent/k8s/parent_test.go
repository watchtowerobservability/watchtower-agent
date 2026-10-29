package k8s

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

func parentCluster(t *testing.T) *cluster {
	t.Helper()
	c := &cluster{namespaces: cache.NewStore(cache.MetaNamespaceKeyFunc), replicasets: cache.NewStore(cache.MetaNamespaceKeyFunc)}
	for name, uid := range map[string]string{"kube-system": "ks-uid", "shop": "shop-uid"} {
		if err := c.namespaces.Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)}}); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-1", UID: "rs-uid",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api", UID: "dep-uid", Controller: &yes}}}}
	if err := c.replicasets.Add(rs); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParentsFormClusterNamespaceWorkloadPod(t *testing.T) {
	c := parentCluster(t)
	if k, id := c.parentOf("namespace", &metav1.ObjectMeta{Name: "shop"}); k != "cluster" || id != "ks-uid" {
		t.Fatalf("namespace parent = %s %s", k, id)
	}
	if k, id := c.parentOf("deployment", &metav1.ObjectMeta{Name: "api", Namespace: "shop"}); k != "namespace" || id != "shop-uid" {
		t.Fatalf("deployment parent = %s %s", k, id)
	}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api-1-x", OwnerReferences: []metav1.OwnerReference{
		{Kind: "ReplicaSet", Name: "api-1", UID: "rs-uid", Controller: &yes}}}}
	// the ReplicaSet collapses to its Deployment
	if k, id := c.podParent(context.Background(), pod); k != "deployment" || id != "dep-uid" {
		t.Fatalf("pod parent = %s %s", k, id)
	}
	bare := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "solo"}}
	if k, id := c.podParent(context.Background(), bare); k != "namespace" || id != "shop-uid" {
		t.Fatalf("bare pod parent = %s %s", k, id)
	}
}
