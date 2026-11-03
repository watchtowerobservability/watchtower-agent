package k8s

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
)

// Target is a pod endpoint that opted in to scraping with annotations:
//
//	watchtower.dev/scrape: "true"
//	watchtower.dev/port: "9102"             (default: the first declared container port)
//	watchtower.dev/path: "/metrics"         (default /metrics)
//	watchtower.dev/integration: "redis"     (an integration manifest name, task I4)
type Target struct {
	Namespace   string
	Pod         string
	UID         string
	IP          string
	Port        int
	Path        string
	Integration string
}

// URL is the scrape URL (plain http inside the cluster).
func (t Target) URL() string {
	return "http://" + t.IP + ":" + strconv.Itoa(t.Port) + t.Path
}

// Discover returns the opted-in targets among pods, sorted by namespace, pod and port. A pod
// without an IP, one that is not running, or with an unusable port or path is skipped; the
// annotations are untrusted input from whoever can edit pods.
func Discover(pods []*corev1.Pod) []Target {
	var out []Target
	for _, p := range pods {
		if t, why := Explain(p); why == "" {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Pod != b.Pod {
			return a.Pod < b.Pod
		}
		return a.Port < b.Port
	})
	return out
}

// Explain resolves one pod to its scrape target, or says why it is not scraped (`wtctl k8s
// doctor` prints the reason). why is "" when the pod is a target.
func Explain(p *corev1.Pod) (Target, string) {
	a := p.Annotations
	switch {
	case a[AnnPrefix+"scrape"] != "true":
		return Target{}, AnnPrefix + `scrape is not "true"`
	case p.Status.PodIP == "":
		return Target{}, "the pod has no IP yet"
	case p.Status.Phase != corev1.PodRunning:
		return Target{}, "the pod is " + string(p.Status.Phase) + ", not Running"
	}
	port, ok := scrapePort(p)
	if !ok {
		return Target{}, AnnPrefix + "port is not a port number and no container declares a port"
	}
	path := a[AnnPrefix+"path"]
	if path == "" {
		path = "/metrics"
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\r\n#") || len(path) > 200 {
		return Target{}, AnnPrefix + "path must start with / and hold no spaces or #"
	}
	integ := a[AnnPrefix+"integration"]
	if len(integ) > 100 {
		return Target{}, AnnPrefix + "integration is longer than 100 characters"
	}
	return Target{Namespace: p.Namespace, Pod: p.Name, UID: string(p.UID), IP: p.Status.PodIP,
		Port: port, Path: path, Integration: integ}, ""
}

func scrapePort(p *corev1.Pod) (int, bool) {
	if s := p.Annotations[AnnPrefix+"port"]; s != "" {
		n, err := strconv.Atoi(s)
		return n, err == nil && n > 0 && n < 65536
	}
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			if cp.ContainerPort > 0 {
				return int(cp.ContainerPort), true
			}
		}
	}
	return 0, false
}

var discovered atomic.Pointer[[]Target]

// Targets is the node agent's current discovery result (nil before the first poll or when the
// node agent is not running). The integrations module (I4) turns these into scrapes.
func Targets() []Target {
	if p := discovered.Load(); p != nil {
		return *p
	}
	return nil
}

// ControlPlaneURLs resolves a control-plane component ("scheduler", "controller-manager",
// "etcd") to the metrics URLs of its kube-system static pods (label component=<name>), on the
// pod IP and kubeadm's default port. Pods that are not running are skipped.
func ControlPlaneURLs(pods []*corev1.Pod, component string) []string {
	c, ok := controlPlaneLabels[component]
	if !ok {
		return nil
	}
	var out []string
	for _, p := range pods {
		if p.Namespace != "kube-system" || p.Labels["component"] != c.label || p.Status.PodIP == "" || p.Status.Phase != corev1.PodRunning {
			continue
		}
		out = append(out, "https://"+net.JoinHostPort(p.Status.PodIP, strconv.Itoa(c.port))+"/metrics")
	}
	sort.Strings(out)
	return out
}
