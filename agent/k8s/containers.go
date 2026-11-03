package k8s

import (
	"strings"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
)

// ContainerRef is the pod a running container belongs to (for eBPF flow attribution, INF-038).
type ContainerRef struct {
	Namespace, Pod, Container string
	// Workload is the controlling object as kind/name; a ReplicaSet with a pod-template-hash is
	// folded into its Deployment so flows group by what users deploy.
	Workload string
}

// IndexContainers maps runtime container ids (the 64-hex id without the `containerd://` scheme)
// of the given pods to their pod.
func IndexContainers(pods []*corev1.Pod) map[string]ContainerRef {
	out := map[string]ContainerRef{}
	for _, p := range pods {
		w := ""
		if o := controllerRef(p.OwnerReferences); o != nil {
			w = strings.ToLower(o.Kind) + "/" + o.Name
			if h := p.Labels["pod-template-hash"]; o.Kind == "ReplicaSet" && h != "" {
				w = "deployment/" + strings.TrimSuffix(o.Name, "-"+h)
			}
		}
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			if _, id, ok := strings.Cut(cs.ContainerID, "://"); ok && id != "" {
				out[id] = ContainerRef{Namespace: p.Namespace, Pod: p.Name, Container: cs.Name, Workload: w}
			}
		}
	}
	return out
}

var containerIndex atomic.Pointer[map[string]ContainerRef]

// ContainerByID looks a container id up in the node agent's latest pod list (false before the
// first poll, off-cluster, or for containers that are not pods').
func ContainerByID(id string) (ContainerRef, bool) {
	if m := containerIndex.Load(); m != nil {
		r, ok := (*m)[id]
		return r, ok
	}
	return ContainerRef{}, false
}
