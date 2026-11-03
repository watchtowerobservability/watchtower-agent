package k8s

import (
	"context"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Explorer facts (INF-009) and pod manifests (INF-004): requests and limits, node conditions and
// the one-time pod spec record.

// WorkloadOf is the kind and uid of the pod's workload (a ReplicaSet collapsed to its Deployment,
// a Job to its CronJob); "" when the pod has none.
func WorkloadOf(ctx context.Context, p *corev1.Pod, look Lookup) (string, string) {
	if chain := Chain(ctx, p.Namespace, p.OwnerReferences, look); len(chain) > 0 {
		top := chain[len(chain)-1]
		if k := kindKey(top.Kind); workloadKinds[k] && top.UID != "" {
			return k, string(top.UID)
		}
	}
	return "", ""
}

func merge(a, b map[string]string) map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

var resourceKeys = [4]struct {
	name string
	cpu  bool
	lim  bool
}{{"cpu.request", true, false}, {"cpu.limit", true, true}, {"memory.request", false, false}, {"memory.limit", false, true}}

// ResourceProps are the container requests and limits of a pod spec summed and times n pods, as
// entity properties k8s.<kind>.{cpu,memory}.{request,limit} (cores, bytes), so the explorer can
// show usage against them. A sum is left out when any container lacks the value; those
// containers are named in k8s.<kind>.requests_missing / .limits_missing (the risk checks).
func ResourceProps(kind string, spec *corev1.PodSpec, n int32) map[string]string {
	p := "k8s." + kind + "."
	out := map[string]string{}
	if len(spec.Containers) == 0 {
		return out
	}
	var sums [4]float64
	var missing [4]bool
	var noReq, noLim []string
	for _, c := range spec.Containers {
		lacksReq, lacksLim := false, false
		for i, k := range resourceKeys {
			l, r := c.Resources.Requests, corev1.ResourceMemory
			if k.lim {
				l = c.Resources.Limits
			}
			if k.cpu {
				r = corev1.ResourceCPU
			}
			q, ok := l[r]
			if !ok {
				missing[i] = true
				if k.lim {
					lacksLim = true
				} else {
					lacksReq = true
				}
				continue
			}
			sums[i] += q.AsApproximateFloat64()
		}
		if lacksReq {
			noReq = append(noReq, c.Name)
		}
		if lacksLim {
			noLim = append(noLim, c.Name)
		}
	}
	for i, k := range resourceKeys {
		if !missing[i] {
			out[p+k.name] = strconv.FormatFloat(sums[i]*float64(n), 'f', -1, 64)
		}
	}
	if len(noReq) > 0 {
		out[p+"requests_missing"] = strings.Join(noReq, ",")
	}
	if len(noLim) > 0 {
		out[p+"limits_missing"] = strings.Join(noLim, ",")
	}
	return out
}

// NodeProps are a node's entity properties for the node page: every condition the kubelet or a
// node-problem-detector reports (k8s.node.condition.<Type> = True/False/Unknown) and the
// allocatable CPU (cores) and memory (bytes).
func NodeProps(n *corev1.Node) map[string]string {
	out := map[string]string{}
	for _, c := range n.Status.Conditions {
		out["k8s.node.condition."+string(c.Type)] = string(c.Status)
	}
	if q, ok := n.Status.Allocatable[corev1.ResourceCPU]; ok {
		out["k8s.node.allocatable_cpu"] = strconv.FormatFloat(q.AsApproximateFloat64(), 'g', -1, 64)
	}
	if q, ok := n.Status.Allocatable[corev1.ResourceMemory]; ok {
		out["k8s.node.allocatable_memory"] = strconv.FormatInt(q.Value(), 10)
	}
	return out
}

// snapshotPod logs the trimmed manifest of a pod once (the pod YAML view): a pod's spec is
// immutable apart from images, whose changes onPodUpdate logs. A pod the limiter skips gets its
// record on a later update or informer resync.
func (c *cluster) snapshotPod(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok || c.snapped.has(p.UID) || !c.lim.allow(time.Now()) {
		return
	}
	c.snapped.fresh(p.UID, 1)
	a := c.objRes("pod", p, nil)
	a["k8s.object.kind"] = "pod"
	a["k8s.object.change.fields"] = "created"
	a["k8s.object.manifest"] = Manifest(p)
	c.out.Log("INFO", "pod "+p.Namespace+"/"+p.Name+" spec recorded", a, time.Now())
}

// onPodUpdate logs an image change of a running pod, then makes sure its spec was recorded.
func (c *cluster) onPodUpdate(oldObj, newObj any) {
	o, ok1 := oldObj.(*corev1.Pod)
	n, ok2 := newObj.(*corev1.Pod)
	if !ok1 || !ok2 {
		return
	}
	if c.snapped.has(n.UID) {
		c.logChange("pod", o, n, SpecAttrs("pod", &o.Spec, nil, nil), SpecAttrs("pod", &n.Spec, nil, nil))
	}
	c.snapshotPod(n)
}

func (c *cluster) onPodDelete(obj any) {
	if p, ok := obj.(*corev1.Pod); ok {
		c.snapped.forget(p.UID)
	}
}
