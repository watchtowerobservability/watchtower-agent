// Package k8s is the Kubernetes side of wt-agent: a node agent (DaemonSet: kubelet usage metrics,
// pod logs, scrape discovery) and a cluster agent (one elected Deployment replica: object state
// metrics, events, spec-change history). Both use client-go with read-only RBAC and never read
// Secret objects or the env of any pod spec.
package k8s

import (
	"context"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Lookup returns the controller owner of the ReplicaSet or Job called name in ns.
type Lookup func(ctx context.Context, kind, ns, name string) (*metav1.OwnerReference, bool)

const maxChain = 4

// controllerRef is the controlling owner, or the first owner when none is marked.
func controllerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	if len(refs) > 0 {
		return &refs[0]
	}
	return nil
}

// Chain walks pod -> owner -> owner...: a ReplicaSet continues to its Deployment and a Job to its
// CronJob (through look); any other owner kind ends the chain. The first element is the direct
// owner.
func Chain(ctx context.Context, ns string, refs []metav1.OwnerReference, look Lookup) []metav1.OwnerReference {
	var out []metav1.OwnerReference
	cur := controllerRef(refs)
	for i := 0; cur != nil && i < maxChain; i++ {
		out = append(out, *cur)
		if look == nil || (cur.Kind != "ReplicaSet" && cur.Kind != "Job") {
			break
		}
		next, ok := look(ctx, cur.Kind, ns, cur.Name)
		if !ok {
			break
		}
		cur = next
	}
	return out
}

// kindKey turns a Kind into the attribute segment: lower case letters and digits only, so
// "ReplicaSet" is "replicaset" and the worker's k8s.<kind>.uid rule applies.
func kindKey(kind string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(kind) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// OwnerAttrs is k8s.<kind>.name for each owner in the chain (resource attributes). Owners are
// named but never given a .uid here: the worker makes an entity of every k8s.<kind>.uid it sees,
// and an owner's entity must come only from the owner's own state metrics, which carry its spec.
func OwnerAttrs(chain []metav1.OwnerReference) map[string]string {
	out := map[string]string{}
	for _, o := range chain {
		k := kindKey(o.Kind)
		if k == "" {
			continue
		}
		out["k8s."+k+".name"] = o.Name
	}
	return out
}

// PodAttrs are the resource attributes every record about a pod carries (INF-007): cluster,
// namespace, pod, node and the owner chain. No `wt.*` key is ever set.
func PodAttrs(ctx context.Context, cluster string, pod *corev1.Pod, look Lookup) map[string]string {
	a := map[string]string{
		"k8s.namespace.name": pod.Namespace,
		"k8s.pod.name":       pod.Name,
		"k8s.pod.uid":        string(pod.UID),
	}
	if cluster != "" {
		a["k8s.cluster.name"] = cluster
	}
	if pod.Spec.NodeName != "" {
		a["k8s.node.name"] = pod.Spec.NodeName
	}
	for k, v := range OwnerAttrs(Chain(ctx, pod.Namespace, pod.OwnerReferences, look)) {
		a[k] = v
	}
	return a
}

const (
	ownerTTL = 10 * time.Minute
	ownerCap = 5000
	apiWait  = 5 * time.Second
)

type cachedOwner struct {
	ref *metav1.OwnerReference
	at  time.Time
}

// evictOwners makes room in a full owner cache: expired entries go first (they would be
// re-fetched on the next miss anyway), and if every entry is still fresh the single oldest one is
// dropped, so the map never grows past capN.
func evictOwners(cache map[string]cachedOwner, capN int, now time.Time) {
	if len(cache) < capN {
		return
	}
	for k, v := range cache {
		if now.Sub(v.at) >= ownerTTL {
			delete(cache, k)
		}
	}
	if len(cache) < capN {
		return
	}
	var oldest string
	var at time.Time
	for k, v := range cache {
		if oldest == "" || v.at.Before(at) {
			oldest, at = k, v.at
		}
	}
	delete(cache, oldest)
}

// NewAPILookup resolves ReplicaSet and Job owners with one GET each, cached for ten minutes in
// at most 5000 entries, evicting expired entries (then the oldest) when full. The node agent uses
// it so it needs no cluster-wide ReplicaSet watch.
func NewAPILookup(cs kubernetes.Interface) Lookup {
	var mu sync.Mutex
	cache := map[string]cachedOwner{}
	return func(ctx context.Context, kind, ns, name string) (*metav1.OwnerReference, bool) {
		key := kind + "/" + ns + "/" + name
		mu.Lock()
		c, ok := cache[key]
		mu.Unlock()
		if ok && time.Since(c.at) < ownerTTL {
			return c.ref, c.ref != nil
		}
		ctx, cancel := context.WithTimeout(ctx, apiWait)
		defer cancel()
		var refs []metav1.OwnerReference
		var err error
		switch kind {
		case "ReplicaSet":
			rs, e := cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
			if e == nil {
				refs = rs.OwnerReferences
			}
			err = e
		case "Job":
			j, e := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
			if e == nil {
				refs = j.OwnerReferences
			}
			err = e
		default:
			return nil, false
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, false // transient: not cached, try again next time
		}
		ref := controllerRef(refs)
		mu.Lock()
		evictOwners(cache, ownerCap, time.Now())
		cache[key] = cachedOwner{ref: ref, at: time.Now()}
		mu.Unlock()
		return ref, ref != nil
	}
}
