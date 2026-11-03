package k8s

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// AnnPrefix is the pod annotation namespace the agent reads (autodiscovery).
const AnnPrefix = "watchtower.dev/"

// Informer transforms. They run before an object is stored, so the cache holds only what the
// agent uses: names, owners, status counters, images and resources. Env, EnvFrom, command, args,
// volumes and annotations (other than ours) are dropped on arrival: the agent never keeps a
// value that could be a credential, and large clusters stay small in memory.

// slim keeps identity, owners and (optionally) labels of an object, plus our annotations.
func slim(m metav1.ObjectMeta, labels bool) metav1.ObjectMeta {
	o := metav1.ObjectMeta{
		Name: m.Name, Namespace: m.Namespace, UID: m.UID, ResourceVersion: m.ResourceVersion,
		OwnerReferences: m.OwnerReferences, CreationTimestamp: m.CreationTimestamp,
		DeletionTimestamp: m.DeletionTimestamp,
	}
	if labels {
		o.Labels = m.Labels
	}
	for k, v := range m.Annotations {
		if strings.HasPrefix(k, AnnPrefix) || strings.HasPrefix(k, AdPrefix) {
			if o.Annotations == nil {
				o.Annotations = map[string]string{}
			}
			o.Annotations[k] = v
		}
	}
	return o
}

func podSpec(s corev1.PodSpec) corev1.PodSpec {
	keep := func(in []corev1.Container) []corev1.Container {
		out := make([]corev1.Container, 0, len(in))
		for _, c := range in {
			t := corev1.Container{Name: c.Name, Image: c.Image,
				Resources: corev1.ResourceRequirements{Requests: c.Resources.Requests, Limits: c.Resources.Limits}}
			for _, p := range c.Ports {
				t.Ports = append(t.Ports, corev1.ContainerPort{ContainerPort: p.ContainerPort})
			}
			out = append(out, t)
		}
		return out
	}
	return corev1.PodSpec{NodeName: s.NodeName, Containers: keep(s.Containers), InitContainers: keep(s.InitContainers)}
}

func trimPod(p *corev1.Pod) *corev1.Pod {
	t := &corev1.Pod{ObjectMeta: slim(p.ObjectMeta, false), Spec: podSpec(p.Spec)}
	t.Status.Phase, t.Status.PodIP = p.Status.Phase, p.Status.PodIP
	for _, c := range p.Status.Conditions {
		t.Status.Conditions = append(t.Status.Conditions, corev1.PodCondition{Type: c.Type, Status: c.Status})
	}
	cs := func(in []corev1.ContainerStatus) []corev1.ContainerStatus {
		out := make([]corev1.ContainerStatus, 0, len(in))
		for _, c := range in {
			o := corev1.ContainerStatus{Name: c.Name, Ready: c.Ready, RestartCount: c.RestartCount}
			if w := c.State.Waiting; w != nil {
				o.State.Waiting = &corev1.ContainerStateWaiting{Reason: w.Reason}
			}
			if x := c.State.Terminated; x != nil {
				o.State.Terminated = &corev1.ContainerStateTerminated{Reason: x.Reason, ExitCode: x.ExitCode}
			}
			if x := c.LastTerminationState.Terminated; x != nil {
				o.LastTerminationState.Terminated = &corev1.ContainerStateTerminated{Reason: x.Reason, ExitCode: x.ExitCode}
			}
			out = append(out, o)
		}
		return out
	}
	t.Status.ContainerStatuses = cs(p.Status.ContainerStatuses)
	t.Status.InitContainerStatuses = cs(p.Status.InitContainerStatuses)
	return t
}

// Trim is the cache.TransformFunc for every informer of this package. Unknown types pass through
// unchanged (tombstones included).
func Trim(obj any) (any, error) {
	switch o := obj.(type) {
	case *corev1.Pod:
		return trimPod(o), nil
	case *appsv1.Deployment:
		return &appsv1.Deployment{ObjectMeta: slim(o.ObjectMeta, true),
			Spec:   appsv1.DeploymentSpec{Replicas: o.Spec.Replicas, Template: corev1.PodTemplateSpec{Spec: podSpec(o.Spec.Template.Spec)}},
			Status: appsv1.DeploymentStatus{AvailableReplicas: o.Status.AvailableReplicas, ReadyReplicas: o.Status.ReadyReplicas, UpdatedReplicas: o.Status.UpdatedReplicas, UnavailableReplicas: o.Status.UnavailableReplicas}}, nil
	case *appsv1.ReplicaSet:
		return &appsv1.ReplicaSet{ObjectMeta: slim(o.ObjectMeta, false),
			Spec:   appsv1.ReplicaSetSpec{Replicas: o.Spec.Replicas},
			Status: appsv1.ReplicaSetStatus{AvailableReplicas: o.Status.AvailableReplicas, ReadyReplicas: o.Status.ReadyReplicas}}, nil
	case *appsv1.StatefulSet:
		return &appsv1.StatefulSet{ObjectMeta: slim(o.ObjectMeta, true),
			Spec:   appsv1.StatefulSetSpec{Replicas: o.Spec.Replicas, Template: corev1.PodTemplateSpec{Spec: podSpec(o.Spec.Template.Spec)}},
			Status: appsv1.StatefulSetStatus{ReadyReplicas: o.Status.ReadyReplicas, CurrentReplicas: o.Status.CurrentReplicas, UpdatedReplicas: o.Status.UpdatedReplicas}}, nil
	case *appsv1.DaemonSet:
		return &appsv1.DaemonSet{ObjectMeta: slim(o.ObjectMeta, true),
			Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: podSpec(o.Spec.Template.Spec)}},
			Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: o.Status.DesiredNumberScheduled, CurrentNumberScheduled: o.Status.CurrentNumberScheduled,
				NumberReady: o.Status.NumberReady, NumberMisscheduled: o.Status.NumberMisscheduled}}, nil
	case *batchv1.Job:
		return &batchv1.Job{ObjectMeta: slim(o.ObjectMeta, false),
			Spec:   batchv1.JobSpec{Completions: o.Spec.Completions},
			Status: batchv1.JobStatus{Active: o.Status.Active, Failed: o.Status.Failed, Succeeded: o.Status.Succeeded}}, nil
	case *batchv1.CronJob:
		return &batchv1.CronJob{ObjectMeta: slim(o.ObjectMeta, true),
			Spec:   batchv1.CronJobSpec{Suspend: o.Spec.Suspend, JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec(o.Spec.JobTemplate.Spec.Template.Spec)}}}},
			Status: batchv1.CronJobStatus{Active: o.Status.Active}}, nil
	case *corev1.Node:
		n := &corev1.Node{ObjectMeta: slim(o.ObjectMeta, false)}
		n.Status.Allocatable = o.Status.Allocatable
		for _, c := range o.Status.Conditions {
			n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{Type: c.Type, Status: c.Status})
		}
		return n, nil
	case *corev1.Namespace:
		return &corev1.Namespace{ObjectMeta: slim(o.ObjectMeta, false), Status: corev1.NamespaceStatus{Phase: o.Status.Phase}}, nil
	case *corev1.Service:
		return &corev1.Service{ObjectMeta: slim(o.ObjectMeta, false), Spec: corev1.ServiceSpec{Type: o.Spec.Type}}, nil
	case *netv1.Ingress:
		return &netv1.Ingress{ObjectMeta: slim(o.ObjectMeta, false), Spec: netv1.IngressSpec{IngressClassName: o.Spec.IngressClassName}}, nil
	case *netv1.NetworkPolicy:
		return &netv1.NetworkPolicy{ObjectMeta: slim(o.ObjectMeta, false), Spec: o.Spec}, nil
	case *corev1.PersistentVolumeClaim:
		return &corev1.PersistentVolumeClaim{ObjectMeta: slim(o.ObjectMeta, false),
			Spec:   corev1.PersistentVolumeClaimSpec{StorageClassName: o.Spec.StorageClassName},
			Status: corev1.PersistentVolumeClaimStatus{Phase: o.Status.Phase, Capacity: o.Status.Capacity}}, nil
	case *corev1.Event:
		msg := sink.Truncate(o.Message, maxEventMessage)
		return &corev1.Event{ObjectMeta: slim(o.ObjectMeta, false), InvolvedObject: corev1.ObjectReference{
			Kind: o.InvolvedObject.Kind, Name: o.InvolvedObject.Name, Namespace: o.InvolvedObject.Namespace, UID: o.InvolvedObject.UID},
			Reason: o.Reason, Message: msg, Type: o.Type, Count: o.Count, FirstTimestamp: o.FirstTimestamp, LastTimestamp: o.LastTimestamp,
			EventTime: o.EventTime, Series: o.Series}, nil
	}
	return obj, nil
}

const (
	maxEventMessage = 4096
	maxSpecAttr     = 1000  // the worker drops attribute values over 1024 bytes
	maxManifest     = 15000 // log attribute values are cut at 16 KiB on ingest
)

// Manifest renders an object as the informer keeps it (already trimmed by Trim: no env, command,
// args, volumes or foreign annotations) as YAML with sorted keys, without status and resource
// version, so two versions differ only where the spec or labels did (INF-004). Cut to
// maxManifest bytes; "" when the object does not marshal.
func Manifest(obj any) string {
	b, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	delete(m, "status")
	if md, ok := m["metadata"].(map[string]any); ok {
		delete(md, "resourceVersion")
	}
	y, err := yaml.Marshal(m)
	if err != nil {
		return ""
	}
	return sink.Truncate(string(y), maxManifest)
}

// SpecAttrs are the spec facts the worker records in entity history when they change, as
// resource attributes of the object: k8s.<kind>.spec.{image,replicas,resources,labels}. Values
// are deterministic (declared container order, sorted labels) and cut to maxSpecAttr bytes.
func SpecAttrs(kind string, spec *corev1.PodSpec, replicas *int32, labels map[string]string) map[string]string {
	p := "k8s." + kind + ".spec."
	out := map[string]string{}
	if spec != nil {
		var imgs, res []string
		for _, c := range spec.Containers {
			imgs = append(imgs, c.Name+"="+c.Image)
			if r := resourceString(c); r != "" {
				res = append(res, c.Name+":"+r)
			}
		}
		out[p+"image"] = sink.Truncate(strings.Join(imgs, ","), maxSpecAttr)
		if len(res) > 0 {
			out[p+"resources"] = sink.Truncate(strings.Join(res, ";"), maxSpecAttr)
		}
	}
	if replicas != nil {
		out[p+"replicas"] = fmt.Sprint(*replicas)
	}
	if len(labels) > 0 {
		kv := make([]string, 0, len(labels))
		for k, v := range labels {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
		out[p+"labels"] = sink.Truncate(strings.Join(kv, ","), maxSpecAttr)
	}
	return out
}

func resourceString(c corev1.Container) string {
	var parts []string
	add := func(tag string, l corev1.ResourceList, n corev1.ResourceName) {
		if q, ok := l[n]; ok {
			parts = append(parts, tag+"="+q.String())
		}
	}
	add("cpu_req", c.Resources.Requests, corev1.ResourceCPU)
	add("cpu_lim", c.Resources.Limits, corev1.ResourceCPU)
	add("mem_req", c.Resources.Requests, corev1.ResourceMemory)
	add("mem_lim", c.Resources.Limits, corev1.ResourceMemory)
	return strings.Join(parts, ",")
}
