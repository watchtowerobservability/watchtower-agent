package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
)

// fetchFunc GETs an API server path (absolute, with query).
type fetchFunc func(ctx context.Context, path string) ([]byte, error)

func restFetch(cs kubernetes.Interface) fetchFunc {
	return func(ctx context.Context, path string) ([]byte, error) {
		return cs.CoreV1().RESTClient().Get().AbsPath(path).DoRaw(ctx)
	}
}

// podMetricsPath is the namespaced PodMetrics list (never the cluster-wide one). The selector is
// applied by the API server.
func podMetricsPath(ns, selector string) string {
	p := "/apis/metrics.k8s.io/v1beta1/namespaces/" + url.PathEscape(ns) + "/pods"
	if selector != "" {
		p += "?labelSelector=" + url.QueryEscape(selector)
	}
	return p
}

type podMetricsList struct {
	Items []struct {
		Metadata   struct{ Name, Namespace string } `json:"metadata"`
		Containers []struct {
			Name  string            `json:"name"`
			Usage map[string]string `json:"usage"`
		} `json:"containers"`
	} `json:"items"`
}

// summaryFromMetrics maps PodMetrics onto the kubelet summary, so Emit reports the same
// k8s.container.cpu.usage / k8s.container.memory.working_set (and k8s.pod.*) as the node path.
func summaryFromMetrics(l *podMetricsList, uid func(ns, name string) (string, bool)) *Summary {
	s := &Summary{}
	for _, it := range l.Items {
		id, ok := uid(it.Metadata.Namespace, it.Metadata.Name)
		if !ok {
			continue // not in the pod cache: out of scope or already gone
		}
		ps := PodStats{PodRef: PodRef{Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, UID: id}, CPU: &CPUStats{}, Memory: &MemStats{}}
		var cpu, mem uint64
		for _, c := range it.Containers {
			cs := ContainerStats{Name: c.Name, CPU: &CPUStats{}, Memory: &MemStats{}}
			if q, err := resource.ParseQuantity(c.Usage["cpu"]); err == nil {
				v := uint64(max(q.ScaledValue(resource.Nano), 0))
				cs.CPU.UsageNanoCores = &v
				cpu += v
			}
			if q, err := resource.ParseQuantity(c.Usage["memory"]); err == nil {
				v := uint64(max(q.Value(), 0))
				cs.Memory.WorkingSetBytes = &v
				mem += v
			}
			ps.Containers = append(ps.Containers, cs)
		}
		ps.CPU.UsageNanoCores, ps.Memory.WorkingSetBytes = &cpu, &mem
		s.Pods = append(s.Pods, ps)
	}
	sort.Slice(s.Pods, func(i, j int) bool { return s.Pods[i].PodRef.UID < s.Pods[j].PodRef.UID })
	return s
}

func (s *scoped) emitMetrics(ctx context.Context, at time.Time) {
	for _, ns := range s.nss {
		body, err := s.fetch(ctx, podMetricsPath(ns, s.cfg.Selector))
		if err != nil {
			slog.Warn("kubernetes: pod metrics unavailable (is metrics-server installed and the Role allowing pods.metrics.k8s.io?)", "namespace", ns, "error", err)
			continue
		}
		var l podMetricsList
		if err := json.Unmarshal(body, &l); err != nil {
			slog.Warn("kubernetes: pod metrics", "namespace", ns, "error", fmt.Errorf("decode: %w", err))
			continue
		}
		sum := summaryFromMetrics(&l, func(ns, name string) (string, bool) {
			if p := s.pod(ns, name); p != nil {
				return string(p.UID), true
			}
			return "", false
		})
		Emit(s.out, sum, nil, func(r PodRef) map[string]string {
			p := s.pod(r.Namespace, r.Name)
			a := PodAttrs(ctx, s.cfg.ClusterName, p, s.cl.lookup)
			if _, uid := WorkloadOf(ctx, p, s.cl.lookup); uid != "" {
				a["k8s.parent.id"] = uid
			}
			a["host.name"] = p.Spec.NodeName
			return a
		}, at)
	}
}
