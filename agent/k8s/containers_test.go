package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIndexContainersFoldsReplicaSetIntoDeployment(t *testing.T) {
	ctrl := true
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "cart-7d9f-x2", Labels: map[string]string{"pod-template-hash": "7d9f"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "cart-7d9f", Controller: &ctrl}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: "containerd://abc123"}, {Name: "pending"}}},
	}
	idx := IndexContainers([]*corev1.Pod{p})
	r, ok := idx["abc123"]
	if !ok || len(idx) != 1 || r.Pod != "cart-7d9f-x2" || r.Container != "app" || r.Workload != "deployment/cart" {
		t.Fatalf("idx %+v", idx)
	}
}
