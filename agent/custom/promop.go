package custom

// Prometheus Operator CRDs as a discovery source (CFT-A03): ServiceMonitor, PodMonitor, Probe and
// ScrapeConfig objects (monitoring.coreos.com) become scrape targets, so clusters that already
// ship them need no Watchtower-specific config. sd type "prometheus_operator"; `kinds` limits
// the CRDs (default all), `namespaces` where the CRD objects are read (default all), `selector`
// a label selector on the CRD objects. Missing CRDs (404) count as none.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// kubeRaw GETs a raw API path; tests replace it.
var kubeRaw = func(ctx context.Context, cs kubernetes.Interface, path string) ([]byte, error) {
	return cs.CoreV1().RESTClient().Get().AbsPath(path).DoRaw(ctx)
}

type opRelabel struct {
	SourceLabels []string `json:"sourceLabels"`
	Separator    *string  `json:"separator"`
	TargetLabel  string   `json:"targetLabel"`
	Regex        string   `json:"regex"`
	Modulus      uint64   `json:"modulus"`
	Replacement  *string  `json:"replacement"`
	Action       string   `json:"action"`
}

func convRelabel(in []opRelabel) []RelabelRule {
	out := make([]RelabelRule, 0, len(in))
	for _, r := range in {
		out = append(out, RelabelRule{SourceLabels: r.SourceLabels, Separator: r.Separator, TargetLabel: r.TargetLabel,
			Regex: r.Regex, Modulus: r.Modulus, Replacement: r.Replacement, Action: strings.ToLower(r.Action)})
	}
	return out
}

type opEndpoint struct {
	Port              string              `json:"port"`
	PortNumber        int                 `json:"portNumber"`
	TargetPort        json.RawMessage     `json:"targetPort"`
	Path              string              `json:"path"`
	Scheme            string              `json:"scheme"`
	Interval          string              `json:"interval"`
	ScrapeTimeout     string              `json:"scrapeTimeout"`
	Params            map[string][]string `json:"params"`
	HonorLabels       bool                `json:"honorLabels"`
	Relabelings       []opRelabel         `json:"relabelings"`
	MetricRelabelings []opRelabel         `json:"metricRelabelings"`
}

type opNSSelector struct {
	Any        bool     `json:"any"`
	MatchNames []string `json:"matchNames"`
}

type opObject struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     struct {
		Selector          metav1.LabelSelector `json:"selector"`
		NamespaceSelector opNSSelector         `json:"namespaceSelector"`
		JobLabel          string               `json:"jobLabel"`
		Endpoints         []opEndpoint         `json:"endpoints"`           // ServiceMonitor
		PodEndpoints      []opEndpoint         `json:"podMetricsEndpoints"` // PodMonitor
		// Probe
		JobName  string `json:"jobName"`
		Module   string `json:"module"`
		Interval string `json:"interval"`
		Prober   struct {
			URL    string `json:"url"`
			Scheme string `json:"scheme"`
			Path   string `json:"path"`
		} `json:"prober"`
		Targets struct {
			StaticConfig struct {
				Static []string          `json:"static"`
				Labels map[string]string `json:"labels"`
			} `json:"staticConfig"`
		} `json:"targets"`
		// ScrapeConfig
		StaticConfigs []struct {
			Targets []string          `json:"targets"`
			Labels  map[string]string `json:"labels"`
		} `json:"staticConfigs"`
		HTTPSDConfigs []struct {
			URL string `json:"url"`
		} `json:"httpSDConfigs"`
		MetricsPath string `json:"metricsPath"`
	} `json:"spec"`
}

var opKinds = map[string]string{
	"servicemonitor": "/apis/monitoring.coreos.com/v1/%sservicemonitors",
	"podmonitor":     "/apis/monitoring.coreos.com/v1/%spodmonitors",
	"probe":          "/apis/monitoring.coreos.com/v1/%sprobes",
	"scrapeconfig":   "/apis/monitoring.coreos.com/v1alpha1/%sscrapeconfigs",
}

func (c SDConfig) opList(ctx context.Context, cs kubernetes.Interface, kind string) ([]opObject, error) {
	var out []opObject
	for _, ns := range c.kubeNamespaces() {
		scope := ""
		if ns != "" {
			scope = "namespaces/" + url.PathEscape(ns) + "/"
		}
		p := fmt.Sprintf(opKinds[kind], scope)
		if c.Selector != "" {
			p += "?labelSelector=" + url.QueryEscape(c.Selector)
		}
		b, err := kubeRaw(ctx, cs, p)
		if k8serrors.IsNotFound(err) {
			continue // CRD not installed
		}
		if k8serrors.IsForbidden(err) {
			return nil, fmt.Errorf("sd prometheus_operator %s: forbidden: the agent's ClusterRole needs list on monitoring.coreos.com (shipped in the agent manifests)", kind)
		}
		if err != nil {
			return nil, err
		}
		var l struct {
			Items []opObject `json:"items"`
		}
		if err := json.Unmarshal(b, &l); err != nil {
			return nil, fmt.Errorf("sd prometheus_operator %s: %w", kind, err)
		}
		out = append(out, l.Items...)
	}
	return out, nil
}

func (c SDConfig) operatorSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	cs, err := kubeClient()
	if err != nil {
		return nil, err
	}
	kinds := c.Kinds
	if len(kinds) == 0 {
		kinds = []string{"servicemonitor", "podmonitor", "probe", "scrapeconfig"}
	}
	var out []TargetSpec
	for _, k := range kinds {
		objs, err := c.opList(ctx, cs, k)
		if err != nil {
			return nil, err
		}
		for i := range objs {
			got, err := c.opTargets(ctx, cs, hc, k, &objs[i])
			if err != nil {
				return nil, err
			}
			out = append(out, got...)
		}
	}
	return out, nil
}

func (o *opObject) namespaces() []string {
	switch {
	case o.Spec.NamespaceSelector.Any:
		return []string{metav1.NamespaceAll}
	case len(o.Spec.NamespaceSelector.MatchNames) > 0:
		return o.Spec.NamespaceSelector.MatchNames
	}
	return []string{o.Metadata.Namespace}
}

// apply turns one endpoint into the target's scrape settings and the operator's default labels.
func (e opEndpoint) apply(t TargetSpec, job, kind, name string) TargetSpec {
	u, err := url.Parse(t.URL)
	if err == nil {
		if e.Scheme != "" {
			u.Scheme = strings.ToLower(e.Scheme)
		}
		if e.Path != "" {
			u.Path = e.Path
		}
		if len(e.Params) > 0 {
			u.RawQuery = url.Values(e.Params).Encode()
		}
		t.URL = u.String()
	}
	t.Labels["job"] = job
	t.Labels["__meta_prometheus_operator_"+kind] = name
	t.ScrapeInterval, t.ScrapeTimeout, t.HonorLabels = e.Interval, e.ScrapeTimeout, e.HonorLabels
	t.RelabelConfigs, t.MetricRelabelConfigs = convRelabel(e.Relabelings), convRelabel(e.MetricRelabelings)
	return t
}

func portMatches(e opEndpoint, name string, number int32) bool {
	if e.Port != "" {
		return e.Port == name
	}
	if e.PortNumber > 0 {
		return int32(e.PortNumber) == number
	}
	if len(e.TargetPort) > 0 {
		var n int32
		if json.Unmarshal(e.TargetPort, &n) == nil {
			return n == number
		}
		var s string
		return json.Unmarshal(e.TargetPort, &s) == nil && s == name
	}
	return true
}

func (c SDConfig) opTargets(ctx context.Context, cs kubernetes.Interface, hc *http.Client, kind string, o *opObject) ([]TargetSpec, error) {
	sel, err := metav1.LabelSelectorAsSelector(&o.Spec.Selector)
	if err != nil {
		return nil, nil //nolint:nilerr // a bad selector in one CRD object must not stop discovery
	}
	lo := metav1.ListOptions{LabelSelector: sel.String()}
	name := o.Metadata.Namespace + "/" + o.Metadata.Name
	var out []TargetSpec
	switch kind {
	case "servicemonitor":
		for _, e := range o.Spec.Endpoints {
			for _, ns := range o.namespaces() {
				ts, err := c.kubeEndpoints(ctx, cs, ns, lo, func(_ *corev1.Service, p corev1.EndpointPort) bool { return portMatches(e, p.Name, p.Port) })
				if err != nil {
					return nil, err
				}
				for _, t := range ts {
					job := t.Labels["service"]
					if o.Spec.JobLabel != "" && t.Labels["__meta_kubernetes_service_label_"+metaName(o.Spec.JobLabel)] != "" {
						job = t.Labels["__meta_kubernetes_service_label_"+metaName(o.Spec.JobLabel)]
					}
					out = append(out, e.apply(t, job, kind, name))
				}
			}
		}
	case "podmonitor":
		for _, e := range o.Spec.PodEndpoints {
			for _, ns := range o.namespaces() {
				ts, err := c.kubePods(ctx, cs, ns, lo)
				if err != nil {
					return nil, err
				}
				for _, t := range ts {
					n, _ := strconv.Atoi(t.Labels["__meta_kubernetes_pod_container_port_number"])
					if portMatches(e, t.Labels["__meta_kubernetes_pod_container_port_name"], int32(n)) { //nolint:gosec // a port number
						out = append(out, e.apply(t, o.Metadata.Namespace+"/"+o.Metadata.Name, kind, name))
					}
				}
			}
		}
	case "probe":
		out = append(out, o.probeTargets(name)...)
	case "scrapeconfig":
		got, err := c.scrapeConfigTargets(ctx, hc, o, name)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// probeTargets: each static target is probed through the prober (blackbox-exporter style URL).
func (o *opObject) probeTargets(name string) []TargetSpec {
	p := o.Spec.Prober
	if p.URL == "" {
		return nil
	}
	scheme, path := p.Scheme, p.Path
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/probe"
	}
	job := o.Spec.JobName
	if job == "" {
		job = "probe/" + name
	}
	var out []TargetSpec
	for _, tgt := range o.Spec.Targets.StaticConfig.Static {
		q := url.Values{"target": {tgt}}
		if o.Spec.Module != "" {
			q.Set("module", o.Spec.Module)
		}
		l := map[string]string{"job": job, "instance": tgt, "__meta_prometheus_operator_probe": name}
		for k, v := range o.Spec.Targets.StaticConfig.Labels {
			l[k] = v
		}
		out = append(out, TargetSpec{URL: scheme + "://" + p.URL + path + "?" + q.Encode(), Labels: l, ScrapeInterval: o.Spec.Interval})
	}
	return out
}

func (c SDConfig) scrapeConfigTargets(ctx context.Context, hc *http.Client, o *opObject, name string) ([]TargetSpec, error) {
	path := o.Spec.MetricsPath
	if path == "" {
		path = "/metrics"
	}
	job := "scrapeConfig/" + name
	var groups []fileGroup
	for _, sc := range o.Spec.StaticConfigs {
		groups = append(groups, fileGroup{Targets: sc.Targets, Labels: sc.Labels})
	}
	out := groupSpecs(groups)
	for _, h := range o.Spec.HTTPSDConfigs {
		got, err := SDConfig{Type: "http", URL: h.URL}.httpSD(ctx, hc)
		if err != nil {
			continue // one broken http_sd must not hide the other targets
		}
		out = append(out, got...)
	}
	for i := range out {
		l := clone(out[i].Labels)
		l["job"], l["__meta_prometheus_operator_scrapeconfig"] = job, name
		out[i].Labels = l
		if u, err := url.Parse(out[i].URL); err == nil && u.Path == "/metrics" {
			u.Path = path
			out[i].URL = u.String()
		}
	}
	return out, nil
}
