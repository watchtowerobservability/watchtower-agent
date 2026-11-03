package custom

// kubernetes_sd (CFT-A02): the pod, service, endpoints, node and ingress roles over the API
// server with the pod's service account. Targets carry Prometheus' `__meta_kubernetes_*` labels
// (for relabel_configs; dropped after relabeling) plus namespace/pod/service/node/container.

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	kubeOnce sync.Once
	kubeCS   kubernetes.Interface
	kubeErr  error
	// kubeClient is the in-cluster client; tests replace it.
	kubeClient = func() (kubernetes.Interface, error) {
		kubeOnce.Do(func() {
			rc, err := rest.InClusterConfig()
			if err != nil {
				kubeErr = errors.New("kubernetes sd needs to run in a cluster (service account)")
				return
			}
			kubeCS, kubeErr = kubernetes.NewForConfig(rc)
		})
		return kubeCS, kubeErr
	}
)

func metaName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// objLabels adds labels, label-present and annotations of an object under prefix.
func objLabels(dst map[string]string, prefix string, m metav1.ObjectMeta) {
	for k, v := range m.Labels {
		dst[prefix+"_label_"+metaName(k)] = v
		dst[prefix+"_labelpresent_"+metaName(k)] = "true"
	}
	for k, v := range m.Annotations {
		dst[prefix+"_annotation_"+metaName(k)] = v
	}
}

func (c SDConfig) kubeNamespaces() []string {
	if len(c.Namespaces) == 0 {
		return []string{metav1.NamespaceAll}
	}
	return c.Namespaces
}

func (c SDConfig) kubernetesSD(ctx context.Context) ([]TargetSpec, error) {
	cs, err := kubeClient()
	if err != nil {
		return nil, err
	}
	lo := metav1.ListOptions{LabelSelector: c.Selector}
	if c.Role == "node" { // cluster-scoped
		return c.kubeNodes(ctx, cs, lo)
	}
	var out []TargetSpec
	for _, ns := range c.kubeNamespaces() {
		var got []TargetSpec
		switch c.Role {
		case "pod":
			got, err = c.kubePods(ctx, cs, ns, lo)
		case "service":
			got, err = c.kubeServices(ctx, cs, ns, lo)
		case "endpoints":
			got, err = c.kubeEndpoints(ctx, cs, ns, lo, nil)
		case "ingress":
			got, err = c.kubeIngresses(ctx, cs, ns, lo)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

func podMeta(p *corev1.Pod) map[string]string {
	l := map[string]string{
		"__meta_kubernetes_namespace": p.Namespace, "__meta_kubernetes_pod_name": p.Name, "__meta_kubernetes_pod_ip": p.Status.PodIP,
		"__meta_kubernetes_pod_node_name": p.Spec.NodeName, "__meta_kubernetes_pod_uid": string(p.UID),
		"__meta_kubernetes_pod_phase": string(p.Status.Phase), "__meta_kubernetes_pod_host_ip": p.Status.HostIP,
		"namespace": p.Namespace, "pod": p.Name,
	}
	if len(p.OwnerReferences) > 0 {
		l["__meta_kubernetes_pod_controller_kind"], l["__meta_kubernetes_pod_controller_name"] = p.OwnerReferences[0].Kind, p.OwnerReferences[0].Name
	}
	ready := "false"
	for _, cd := range p.Status.Conditions {
		if cd.Type == corev1.PodReady && cd.Status == corev1.ConditionTrue {
			ready = "true"
		}
	}
	l["__meta_kubernetes_pod_ready"] = ready
	objLabels(l, "__meta_kubernetes_pod", p.ObjectMeta)
	return l
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// kubePods yields one target per declared container port of each running pod with an IP.
func (c SDConfig) kubePods(ctx context.Context, cs kubernetes.Interface, ns string, lo metav1.ListOptions) ([]TargetSpec, error) {
	pods, err := cs.CoreV1().Pods(ns).List(ctx, lo)
	if err != nil {
		return nil, err
	}
	var out []TargetSpec
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.PodIP == "" || p.Status.Phase != corev1.PodRunning {
			continue
		}
		base := podMeta(p)
		for _, ct := range p.Spec.Containers {
			for _, cp := range ct.Ports {
				if cp.Protocol != "" && cp.Protocol != corev1.ProtocolTCP {
					continue
				}
				l := clone(base)
				l["container"], l["__meta_kubernetes_pod_container_name"] = ct.Name, ct.Name
				l["__meta_kubernetes_pod_container_port_name"] = cp.Name
				l["__meta_kubernetes_pod_container_port_number"] = strconv.Itoa(int(cp.ContainerPort))
				out = append(out, TargetSpec{URL: c.scrapeURL(p.Status.PodIP, int(cp.ContainerPort)), Labels: l})
			}
		}
	}
	return out, nil
}

// kubeServices yields one target per service port at the service DNS name (blackbox style).
func (c SDConfig) kubeServices(ctx context.Context, cs kubernetes.Interface, ns string, lo metav1.ListOptions) ([]TargetSpec, error) {
	svcs, err := cs.CoreV1().Services(ns).List(ctx, lo)
	if err != nil {
		return nil, err
	}
	var out []TargetSpec
	for i := range svcs.Items {
		s := &svcs.Items[i]
		for _, sp := range s.Spec.Ports {
			l := map[string]string{"__meta_kubernetes_namespace": s.Namespace, "__meta_kubernetes_service_name": s.Name,
				"__meta_kubernetes_service_port_name": sp.Name, "__meta_kubernetes_service_port_number": strconv.Itoa(int(sp.Port)),
				"__meta_kubernetes_service_type": string(s.Spec.Type), "__meta_kubernetes_service_cluster_ip": s.Spec.ClusterIP,
				"namespace": s.Namespace, "service": s.Name}
			objLabels(l, "__meta_kubernetes_service", s.ObjectMeta)
			out = append(out, TargetSpec{URL: c.scrapeURL(s.Name+"."+s.Namespace+".svc", int(sp.Port)), Labels: l})
		}
	}
	return out, nil
}

// kubeEndpoints yields one target per ready address and port of each service's Endpoints. keep,
// when set, filters services (the ServiceMonitor path) and may name the wanted port.
func (c SDConfig) kubeEndpoints(ctx context.Context, cs kubernetes.Interface, ns string, lo metav1.ListOptions,
	keep func(*corev1.Service, corev1.EndpointPort) bool) ([]TargetSpec, error) {
	svcs, err := cs.CoreV1().Services(ns).List(ctx, lo)
	if err != nil {
		return nil, err
	}
	var out []TargetSpec
	for i := range svcs.Items {
		s := &svcs.Items[i]
		ep, err := cs.CoreV1().Endpoints(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{}) //nolint:staticcheck // EndpointSlice adds nothing we use
		if err != nil {
			continue
		}
		base := map[string]string{"__meta_kubernetes_namespace": s.Namespace, "__meta_kubernetes_service_name": s.Name,
			"__meta_kubernetes_endpoints_name": ep.Name, "namespace": s.Namespace, "service": s.Name}
		objLabels(base, "__meta_kubernetes_service", s.ObjectMeta)
		for _, sub := range ep.Subsets {
			for _, port := range sub.Ports {
				if (port.Protocol != "" && port.Protocol != corev1.ProtocolTCP) || (keep != nil && !keep(s, port)) {
					continue
				}
				for _, a := range sub.Addresses {
					l := clone(base)
					l["__meta_kubernetes_endpoint_port_name"], l["endpoint"] = port.Name, port.Name
					l["__meta_kubernetes_endpoint_ready"] = "true"
					if a.NodeName != nil {
						l["__meta_kubernetes_endpoint_node_name"] = *a.NodeName
					}
					if a.TargetRef != nil && a.TargetRef.Kind == "Pod" {
						l["__meta_kubernetes_pod_name"], l["pod"] = a.TargetRef.Name, a.TargetRef.Name
					}
					out = append(out, TargetSpec{URL: c.scrapeURL(a.IP, int(port.Port)), Labels: l})
				}
			}
		}
	}
	return out, nil
}

func (c SDConfig) kubeIngresses(ctx context.Context, cs kubernetes.Interface, ns string, lo metav1.ListOptions) ([]TargetSpec, error) {
	ings, err := cs.NetworkingV1().Ingresses(ns).List(ctx, lo)
	if err != nil {
		return nil, err
	}
	var out []TargetSpec
	for i := range ings.Items {
		in := &ings.Items[i]
		tls := map[string]bool{}
		for _, t := range in.Spec.TLS {
			for _, h := range t.Hosts {
				tls[h] = true
			}
		}
		for _, r := range in.Spec.Rules {
			if r.Host == "" || r.HTTP == nil {
				continue
			}
			scheme := "http"
			if tls[r.Host] {
				scheme = "https"
			}
			for _, p := range r.HTTP.Paths {
				path := p.Path
				if path == "" {
					path = "/"
				}
				l := map[string]string{"__meta_kubernetes_namespace": in.Namespace, "__meta_kubernetes_ingress_name": in.Name,
					"__meta_kubernetes_ingress_scheme": scheme, "__meta_kubernetes_ingress_path": path, "namespace": in.Namespace, "ingress": in.Name}
				objLabels(l, "__meta_kubernetes_ingress", in.ObjectMeta)
				out = append(out, TargetSpec{URL: scheme + "://" + r.Host + path, Labels: l})
			}
		}
	}
	return out, nil
}

// kubeNodes yields the kubelet of each node (port 10250, https unless the config says otherwise).
func (c SDConfig) kubeNodes(ctx context.Context, cs kubernetes.Interface, lo metav1.ListOptions) ([]TargetSpec, error) {
	nodes, err := cs.CoreV1().Nodes().List(ctx, lo)
	if err != nil {
		return nil, err
	}
	port := c.Port
	if port <= 0 {
		port = 10250
	}
	if c.Scheme == "" {
		c.Scheme = "https"
	}
	var out []TargetSpec
	for i := range nodes.Items {
		n := &nodes.Items[i]
		ip := ""
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP || (ip == "" && a.Type == corev1.NodeExternalIP) {
				ip = a.Address
			}
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		l := map[string]string{"__meta_kubernetes_node_name": n.Name, "node": n.Name}
		objLabels(l, "__meta_kubernetes_node", n.ObjectMeta)
		out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: l})
	}
	return out, nil
}
