package k8s

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// pacedSink slows a big emission so the exporter (20k point buffer, flush check every second)
// can ship it: after every 1500 records it waits one second (or until ctx ends).
type pacedSink struct {
	sink.Sink
	ctx context.Context
	n   int
}

func (p *pacedSink) tick() {
	p.n++
	if p.n%1500 == 0 {
		select {
		case <-p.ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

func (p *pacedSink) Gauge(name, unit string, v float64, a map[string]string, at time.Time) {
	if p.ctx.Err() != nil {
		return // leadership or the agent ended: do not flood the exporter with the rest
	}
	p.Sink.Gauge(name, unit, v, a, at)
	p.tick()
}

func (p *pacedSink) Sum(name, unit string, v float64, a map[string]string, at time.Time) {
	if p.ctx.Err() != nil {
		return
	}
	p.Sink.Sum(name, unit, v, a, at)
	p.tick()
}

// objRes is the resource of one object, addressed with sink.ResourcePrefix: cluster, namespace,
// k8s.<kind>.name and .uid, any extra attributes (spec facts), and an empty host.name so the
// cluster agent's own pod name never becomes the object's host.
func (c *cluster) objRes(kind string, m metav1.Object, extra map[string]string) map[string]string {
	a := map[string]string{"k8s." + kind + ".name": m.GetName(), "k8s." + kind + ".uid": string(m.GetUID()), "host.name": ""}
	if c.cfg.ClusterName != "" {
		a["k8s.cluster.name"] = c.cfg.ClusterName
	}
	if ns := m.GetNamespace(); ns != "" {
		a["k8s.namespace.name"] = ns
	}
	for k, v := range extra {
		a[k] = v
	}
	if pt, pid := c.parentOf(kind, m); pid != "" {
		a["k8s.parent.type"], a["k8s.parent.id"] = pt, pid
	}
	return sink.Res(a)
}

// workloadKinds are the owner kinds a pod's parent can be; any other owner leaves the pod under
// its namespace.
var workloadKinds = map[string]bool{"deployment": true, "statefulset": true, "daemonset": true, "job": true, "cronjob": true, "replicaset": true}

// uidOf is the uid of the object called key in a store ("" when absent).
func uidOf(st cache.Store, key string) string {
	if st == nil {
		return ""
	}
	o, ok, err := st.GetByKey(key)
	if err != nil || !ok {
		return ""
	}
	if m, err := meta.Accessor(o); err == nil {
		return string(m.GetUID())
	}
	return ""
}

// clusterUID is the uid of the kube-system namespace, the cluster's identity ("" when unknown).
func (c *cluster) clusterUID() string { return uidOf(c.namespaces, "kube-system") }

// parentOf is the entity an object hangs under, as (kind, uid): a namespace under the cluster, a
// cluster-scoped object (a node) under the cluster and any other object under its namespace. The
// worker links the entities with these resource attributes (k8s.parent.type and k8s.parent.id).
func (c *cluster) parentOf(kind string, m metav1.Object) (string, string) {
	if kind == "namespace" || m.GetNamespace() == "" {
		return "cluster", c.clusterUID()
	}
	return "namespace", uidOf(c.namespaces, m.GetNamespace())
}

// podParent is the pod's workload (a ReplicaSet collapsed to its Deployment, a Job to its
// CronJob) or, with no such owner, its namespace.
func (c *cluster) podParent(ctx context.Context, p *corev1.Pod) (string, string) {
	if k, uid := WorkloadOf(ctx, p, c.lookup); uid != "" {
		return k, uid
	}
	return "namespace", uidOf(c.namespaces, p.Namespace)
}

// withCounts adds the ready and desired counts of a workload as entity properties (the worker
// merges every k8s.<kind>.* resource attribute that is not a spec fact into the entity), so the
// UI reads them from the entity and not from the metric store.
func withCounts(a map[string]string, kind string, ready, desired int32) map[string]string {
	out := make(map[string]string, len(a)+2)
	for k, v := range a {
		out[k] = v
	}
	out["k8s."+kind+".replicas_ready"] = strconv.Itoa(int(ready))
	out["k8s."+kind+".replicas_desired"] = strconv.Itoa(int(desired))
	return out
}

// podStatus is what kubectl shows as STATUS in short: a container's waiting or terminated reason
// (CrashLoopBackOff, OOMKilled, ...), Terminating, or else the phase.
func podStatus(p *corev1.Pod) string {
	if p.DeletionTimestamp != nil {
		return "Terminating"
	}
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" && cs.State.Terminated.ExitCode != 0 {
			return cs.State.Terminated.Reason
		}
	}
	return string(p.Status.Phase)
}

func podRestarts(p *corev1.Pod) int {
	n := 0
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		n += int(cs.RestartCount)
	}
	return n
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func i32(p *int32) float64 {
	if p == nil {
		return 0
	}
	return float64(*p)
}

func (c *cluster) emitState(ctx context.Context, at time.Time) {
	out := &pacedSink{Sink: c.out, ctx: ctx}
	if uid := c.clusterUID(); uid != "" {
		res := map[string]string{"k8s.cluster.uid": uid, "host.name": ""}
		if c.cfg.ClusterName != "" {
			res["k8s.cluster.name"] = c.cfg.ClusterName
		}
		out.Gauge("k8s.cluster.info", "", 1, sink.Res(res), at)
	}
	c.emitPods(ctx, out, at)
	c.emitNodes(out, at)
	each(c.namespaces, func(n *corev1.Namespace) {
		out.Gauge("k8s.namespace.phase", "", b2f(n.Status.Phase != corev1.NamespaceTerminating), c.objRes("namespace", n, nil), at)
	})
	each(c.deployments, func(d *appsv1.Deployment) {
		r := c.objRes("deployment", d, withCounts(merge(SpecAttrs("deployment", &d.Spec.Template.Spec, d.Spec.Replicas, d.Labels), ResourceProps("deployment", &d.Spec.Template.Spec, int32(i32(d.Spec.Replicas)))), "deployment", d.Status.AvailableReplicas, int32(i32(d.Spec.Replicas))))
		out.Gauge("k8s.deployment.desired", "{pod}", i32(d.Spec.Replicas), r, at)
		out.Gauge("k8s.deployment.available", "{pod}", float64(d.Status.AvailableReplicas), r, at)
		out.Gauge("k8s.deployment.updated", "{pod}", float64(d.Status.UpdatedReplicas), r, at)
	})
	each(c.replicasets, func(s *appsv1.ReplicaSet) {
		r := c.objRes("replicaset", s, nil)
		out.Gauge("k8s.replicaset.desired", "{pod}", i32(s.Spec.Replicas), r, at)
		out.Gauge("k8s.replicaset.available", "{pod}", float64(s.Status.AvailableReplicas), r, at)
	})
	each(c.statefulsets, func(s *appsv1.StatefulSet) {
		r := c.objRes("statefulset", s, withCounts(merge(SpecAttrs("statefulset", &s.Spec.Template.Spec, s.Spec.Replicas, s.Labels), ResourceProps("statefulset", &s.Spec.Template.Spec, int32(i32(s.Spec.Replicas)))), "statefulset", s.Status.ReadyReplicas, int32(i32(s.Spec.Replicas))))
		out.Gauge("k8s.statefulset.desired_pods", "{pod}", i32(s.Spec.Replicas), r, at)
		out.Gauge("k8s.statefulset.ready_pods", "{pod}", float64(s.Status.ReadyReplicas), r, at)
		out.Gauge("k8s.statefulset.current_pods", "{pod}", float64(s.Status.CurrentReplicas), r, at)
		out.Gauge("k8s.statefulset.updated_pods", "{pod}", float64(s.Status.UpdatedReplicas), r, at)
	})
	each(c.daemonsets, func(d *appsv1.DaemonSet) {
		r := c.objRes("daemonset", d, withCounts(merge(SpecAttrs("daemonset", &d.Spec.Template.Spec, nil, d.Labels), ResourceProps("daemonset", &d.Spec.Template.Spec, d.Status.DesiredNumberScheduled)), "daemonset", d.Status.NumberReady, d.Status.DesiredNumberScheduled))
		out.Gauge("k8s.daemonset.desired_scheduled_nodes", "{node}", float64(d.Status.DesiredNumberScheduled), r, at)
		out.Gauge("k8s.daemonset.current_scheduled_nodes", "{node}", float64(d.Status.CurrentNumberScheduled), r, at)
		out.Gauge("k8s.daemonset.ready_nodes", "{node}", float64(d.Status.NumberReady), r, at)
		out.Gauge("k8s.daemonset.misscheduled_nodes", "{node}", float64(d.Status.NumberMisscheduled), r, at)
	})
	each(c.jobs, func(j *batchv1.Job) {
		r := c.objRes("job", j, nil)
		out.Gauge("k8s.job.active_pods", "{pod}", float64(j.Status.Active), r, at)
		out.Gauge("k8s.job.failed_pods", "{pod}", float64(j.Status.Failed), r, at)
		out.Gauge("k8s.job.successful_pods", "{pod}", float64(j.Status.Succeeded), r, at)
		if j.Spec.Completions != nil {
			out.Gauge("k8s.job.desired_successful_pods", "{pod}", float64(*j.Spec.Completions), r, at)
		}
	})
	each(c.cronjobs, func(j *batchv1.CronJob) {
		r := c.objRes("cronjob", j, SpecAttrs("cronjob", &j.Spec.JobTemplate.Spec.Template.Spec, nil, j.Labels))
		out.Gauge("k8s.cronjob.active_jobs", "{job}", float64(len(j.Status.Active)), r, at)
	})
	each(c.services, func(s *corev1.Service) {
		out.Gauge("k8s.service.info", "", 1, sink.With(c.objRes("service", s, nil), "k8s.service.type", string(s.Spec.Type)), at)
	})
	each(c.ingresses, func(i *netv1.Ingress) {
		class := ""
		if i.Spec.IngressClassName != nil {
			class = *i.Spec.IngressClassName
		}
		out.Gauge("k8s.ingress.info", "", 1, sink.With(c.objRes("ingress", i, nil), "k8s.ingress.class", class), at)
	})
	if n := c.lim.takeDropped(); n > 0 {
		out.Gauge("k8s.agent.events.dropped", "{event}", float64(n), sink.Res(map[string]string{"host.name": ""}), at)
	}
	each(c.pvcs, func(p *corev1.PersistentVolumeClaim) {
		r := c.objRes("persistentvolumeclaim", p, nil)
		out.Gauge("k8s.persistentvolumeclaim.phase", "", b2f(p.Status.Phase == corev1.ClaimBound), sink.With(r, "k8s.persistentvolumeclaim.phase", string(p.Status.Phase)), at)
		if q, ok := p.Status.Capacity[corev1.ResourceStorage]; ok {
			out.Gauge("k8s.persistentvolumeclaim.capacity", "By", float64(q.Value()), r, at)
		}
	})
}

// each calls f for every object of type T in the store.
func each[T any](st interface{ List() []any }, f func(T)) {
	if st == nil {
		return
	}
	for _, o := range st.List() {
		if t, ok := o.(T); ok {
			f(t)
		}
	}
}

// phaseNumber follows the OTel k8s.pod.phase encoding.
func phaseNumber(p corev1.PodPhase) float64 {
	switch p {
	case corev1.PodPending:
		return 1
	case corev1.PodRunning:
		return 2
	case corev1.PodSucceeded:
		return 3
	case corev1.PodFailed:
		return 4
	}
	return 5
}

func (c *cluster) emitPods(ctx context.Context, out sink.Sink, at time.Time) {
	each(c.pods, func(p *corev1.Pod) {
		res := sink.Res(PodAttrs(ctx, c.cfg.ClusterName, p, c.lookup))
		res[sink.ResourcePrefix+"host.name"] = p.Spec.NodeName
		res[sink.ResourcePrefix+"k8s.pod.status"] = podStatus(p)
		res[sink.ResourcePrefix+"k8s.pod.restarts"] = strconv.Itoa(podRestarts(p))
		for k, v := range ResourceProps("pod", &p.Spec, 1) {
			res[sink.ResourcePrefix+k] = v
		}
		if pt, pid := c.podParent(ctx, p); pid != "" {
			res[sink.ResourcePrefix+"k8s.parent.type"], res[sink.ResourcePrefix+"k8s.parent.id"] = pt, pid
		}
		out.Gauge("k8s.pod.phase", "", phaseNumber(p.Status.Phase), res, at)
		ready := false
		for _, cd := range p.Status.Conditions {
			if cd.Type == corev1.PodReady {
				ready = cd.Status == corev1.ConditionTrue
			}
		}
		out.Gauge("k8s.pod.ready", "", b2f(ready), res, at)
		statuses := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		for _, cs := range statuses {
			ca := sink.With(res, "k8s.container.name", cs.Name)
			out.Sum("k8s.container.restarts", "{restart}", float64(cs.RestartCount), ca, at)
			out.Gauge("k8s.container.ready", "", b2f(cs.Ready), sink.With(ca, "k8s.container.status.reason", containerReason(cs)), at)
		}
	})
}

// containerReason is the waiting or terminated reason (CrashLoopBackOff, OOMKilled, ...), the
// last termination's reason for a container that is waiting or running again.
func containerReason(cs corev1.ContainerStatus) string {
	switch {
	case cs.State.Waiting != nil && cs.State.Waiting.Reason != "":
		return cs.State.Waiting.Reason
	case cs.State.Terminated != nil && cs.State.Terminated.Reason != "":
		return cs.State.Terminated.Reason
	case cs.LastTerminationState.Terminated != nil:
		return cs.LastTerminationState.Terminated.Reason
	}
	return ""
}

var nodeConditions = map[corev1.NodeConditionType]string{
	corev1.NodeReady:              "k8s.node.condition_ready",
	corev1.NodeMemoryPressure:     "k8s.node.condition_memory_pressure",
	corev1.NodeDiskPressure:       "k8s.node.condition_disk_pressure",
	corev1.NodePIDPressure:        "k8s.node.condition_pid_pressure",
	corev1.NodeNetworkUnavailable: "k8s.node.condition_network_unavailable",
}

func (c *cluster) emitNodes(out sink.Sink, at time.Time) {
	each(c.nodes, func(n *corev1.Node) {
		r := c.objRes("node", n, nil)
		r[sink.ResourcePrefix+"host.name"] = n.Name
		for k, v := range NodeProps(n) {
			r[sink.ResourcePrefix+k] = v
		}
		for _, cd := range n.Status.Conditions {
			if name, ok := nodeConditions[cd.Type]; ok {
				out.Gauge(name, "", b2f(cd.Status == corev1.ConditionTrue), r, at)
			}
		}
		if q, ok := n.Status.Allocatable[corev1.ResourceCPU]; ok {
			out.Gauge("k8s.node.allocatable.cpu", "{cpu}", q.AsApproximateFloat64(), r, at)
		}
		if q, ok := n.Status.Allocatable[corev1.ResourceMemory]; ok {
			out.Gauge("k8s.node.allocatable.memory", "By", float64(q.Value()), r, at)
		}
		if q, ok := n.Status.Allocatable[corev1.ResourcePods]; ok {
			out.Gauge("k8s.node.allocatable.pods", "{pod}", float64(q.Value()), r, at)
		}
	})
}

// onSpecChange logs a k8s.object.change record when image, replicas, resources or labels of a
// workload differ between two versions. The record's resource carries the new spec facts, the
// same attributes the state metrics carry; the worker keeps the entity's history from those.
func (c *cluster) onSpecChange(kind string, oldObj, newObj any) {
	var oldA, newA map[string]string
	var m metav1.Object
	switch n := newObj.(type) {
	case *appsv1.Deployment:
		o, ok := oldObj.(*appsv1.Deployment)
		if !ok {
			return
		}
		oldA = SpecAttrs(kind, &o.Spec.Template.Spec, o.Spec.Replicas, o.Labels)
		newA, m = SpecAttrs(kind, &n.Spec.Template.Spec, n.Spec.Replicas, n.Labels), n
	case *appsv1.StatefulSet:
		o, ok := oldObj.(*appsv1.StatefulSet)
		if !ok {
			return
		}
		oldA = SpecAttrs(kind, &o.Spec.Template.Spec, o.Spec.Replicas, o.Labels)
		newA, m = SpecAttrs(kind, &n.Spec.Template.Spec, n.Spec.Replicas, n.Labels), n
	case *appsv1.DaemonSet:
		o, ok := oldObj.(*appsv1.DaemonSet)
		if !ok {
			return
		}
		oldA = SpecAttrs(kind, &o.Spec.Template.Spec, nil, o.Labels)
		newA, m = SpecAttrs(kind, &n.Spec.Template.Spec, nil, n.Labels), n
	case *batchv1.CronJob:
		o, ok := oldObj.(*batchv1.CronJob)
		if !ok {
			return
		}
		oldA = SpecAttrs(kind, &o.Spec.JobTemplate.Spec.Template.Spec, nil, o.Labels)
		newA, m = SpecAttrs(kind, &n.Spec.JobTemplate.Spec.Template.Spec, nil, n.Labels), n
	case *netv1.NetworkPolicy:
		c.onNetpolChange(oldObj, newObj)
		return
	default:
		return
	}
	c.logChange(kind, oldObj, m, oldA, newA)
}

// logChange logs one k8s.object.change record when a spec fact differs. Besides the changed
// fields it carries both trimmed manifests (k8s.object.manifest and .manifest.previous) that
// ClickHouse keeps as the object's versions (migration 0092).
func (c *cluster) logChange(kind string, oldObj any, m metav1.Object, oldA, newA map[string]string) {
	prefix := "k8s." + kind + ".spec."
	keys := map[string]bool{}
	for k := range oldA {
		keys[k] = true
	}
	for k := range newA {
		keys[k] = true
	}
	var changed []string
	for k := range keys {
		if oldA[k] != newA[k] {
			changed = append(changed, strings.TrimPrefix(k, prefix))
		}
	}
	if len(changed) == 0 || !c.lim.allow(time.Now()) {
		return
	}
	sort.Strings(changed)
	var body strings.Builder
	body.WriteString(kind + " " + m.GetNamespace() + "/" + m.GetName() + " changed:")
	for _, f := range changed {
		body.WriteString("\n" + f + ": " + sink.Truncate(oldA[prefix+f], 200) + " -> " + sink.Truncate(newA[prefix+f], 200))
	}
	a := c.objRes(kind, m, newA)
	a["k8s.object.kind"] = kind
	a["k8s.object.change.fields"] = strings.Join(changed, ",")
	a["k8s.object.manifest"] = Manifest(m)
	a["k8s.object.manifest.previous"] = Manifest(oldObj)
	c.out.Log("INFO", body.String(), a, time.Now())
}
