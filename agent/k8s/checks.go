package k8s

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/integrations"
)

// AdPrefix is the autodiscovery-checks annotation namespace:
//
//	ad.watchtower.dev/<container>.checks: '{"redis":{"instances":[{"host":"%%host%%","port":"%%port%%"}]}}'
//
// The value maps an integration module name to its config; %%host%% becomes the pod IP and
// %%port%% the container's first declared port. No env or secret is ever substituted.
const AdPrefix = "ad.watchtower.dev/"

const (
	maxChecksPerPod = 8
	maxCheckBytes   = 8 << 10
)

// CheckTarget binds one integration module to one container of a running pod.
type CheckTarget struct {
	Namespace string
	Pod       string
	UID       string
	PodIP     string
	Container string
	Module    string
	Config    map[string]any // the module's config with the templates resolved
}

// DiscoverChecks returns the module bindings declared through ad.watchtower.dev annotations on
// running pods with an IP, sorted by namespace, pod, container and module. An annotation that
// names a missing container, is oversized or is not a JSON object of objects is skipped.
func DiscoverChecks(pods []*corev1.Pod) []CheckTarget {
	var out []CheckTarget
	for _, p := range pods {
		if p.Status.PodIP == "" || p.Status.Phase != corev1.PodRunning {
			continue
		}
		n := 0
		for k, v := range p.Annotations {
			ctr, ok := strings.CutPrefix(k, AdPrefix)
			if !ok {
				continue
			}
			ctr, ok = strings.CutSuffix(ctr, ".checks")
			if !ok || len(v) > maxCheckBytes {
				continue
			}
			port, found := containerPort(p, ctr)
			if !found {
				continue
			}
			var mods map[string]map[string]any
			if json.Unmarshal([]byte(v), &mods) != nil {
				continue
			}
			for mod, cfg := range mods {
				if n++; n > maxChecksPerPod || mod == "" || len(mod) > 100 {
					break
				}
				resolved, _ := resolveTemplates(cfg, p.Status.PodIP, port).(map[string]any)
				out = append(out, CheckTarget{Namespace: p.Namespace, Pod: p.Name, UID: string(p.UID), PodIP: p.Status.PodIP,
					Container: ctr, Module: mod, Config: resolved})
			}
		}
	}
	key := func(c CheckTarget) string { return c.Namespace + "/" + c.Pod + "/" + c.Container + "/" + c.Module }
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

// podChecks is the integrations loader's view of this node's annotated pods.
func (n *nodeAgent) podChecks() []integrations.PodCheck {
	var pods []*corev1.Pod
	for _, o := range n.pods.List() {
		if p, ok := o.(*corev1.Pod); ok {
			pods = append(pods, p)
		}
	}
	var out []integrations.PodCheck
	for _, c := range DiscoverChecks(pods) {
		out = append(out, integrations.PodCheck{Namespace: c.Namespace, Pod: c.Pod, UID: c.UID, Container: c.Container,
			Module: c.Module, PodIP: c.PodIP, Config: c.Config})
	}
	return out
}

// containerPort reports whether the pod has the container, and its first declared port (0 if none).
func containerPort(p *corev1.Pod, name string) (int, bool) {
	for _, c := range p.Spec.Containers {
		if c.Name != name {
			continue
		}
		for _, cp := range c.Ports {
			if cp.ContainerPort > 0 {
				return int(cp.ContainerPort), true
			}
		}
		return 0, true
	}
	return 0, false
}

// resolveTemplates substitutes %%host%% and %%port%% in every string of v (recursively).
func resolveTemplates(v any, host string, port int) any {
	switch x := v.(type) {
	case string:
		return strings.NewReplacer("%%host%%", host, "%%port%%", strconv.Itoa(port)).Replace(x)
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = resolveTemplates(e, host, port)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = resolveTemplates(e, host, port)
		}
		return s
	}
	return v
}
