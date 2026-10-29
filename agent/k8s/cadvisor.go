package k8s

import (
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// cadvisorLabels maps cAdvisor's labels to OTel k8s resource attributes. id and name (cgroup
// paths) are dropped: they are noisy and unbounded.
var cadvisorLabels = map[string]string{
	"namespace": "k8s.namespace.name",
	"pod":       "k8s.pod.name",
	"container": "k8s.container.name",
	"image":     "container.image.name",
}

// CadvisorAttrs turns one container_* series' labels into resource attributes plus the point
// attributes that stay on the series (interface, device, cpu ...). ok is false for series that
// belong to no workload (the root cgroup) or to the pause container.
func CadvisorAttrs(labels map[string]string, node, cluster string) (res, point map[string]string, ok bool) {
	if labels["pod"] == "" || labels["container"] == "POD" {
		return nil, nil, false
	}
	res = map[string]string{"k8s.node.name": node, "host.name": node}
	if cluster != "" {
		res["k8s.cluster.name"] = cluster
	}
	point = map[string]string{}
	for k, v := range labels {
		if to, mapped := cadvisorLabels[k]; mapped {
			if v != "" {
				res[to] = v
			}
			continue
		}
		if k != "id" && k != "name" {
			point[k] = v
		}
	}
	return res, point, true
}

// EmitCadvisor forwards the container_* families under their original names (so cAdvisor
// dashboards work) with the workload on the resource.
func EmitCadvisor(out sink.Sink, fams map[string]*dto.MetricFamily, node, cluster string, at time.Time) {
	for name, fam := range fams {
		if !strings.HasPrefix(name, "container_") {
			continue
		}
		for _, m := range fam.GetMetric() {
			lbl := make(map[string]string, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				lbl[l.GetName()] = l.GetValue()
			}
			res, point, ok := CadvisorAttrs(lbl, node, cluster)
			if !ok {
				continue
			}
			a := sink.Res(res)
			for k, v := range sink.Strip(point) {
				a[k] = v
			}
			forwardMetric(out, fam.GetType(), name, m, a, at)
		}
	}
}
