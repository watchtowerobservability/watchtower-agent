package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// External metrics (INF-008, Datadog Cluster Agent external metrics provider): the
// `external_metrics` module serves external.metrics.k8s.io/v1beta1 so an HPA can scale on any
// Watchtower metric. Each exposed metric is a named PromQL query in the local config; the HPA's
// metric selector becomes extra label matchers through the `{{selector}}` placeholder, e.g.
//
//	metrics: {queue_lag: 'sum(kafka_consumergroup_lag{ {{selector}} })'}
//
// Every agent pod can answer (it is stateless), so the chart's APIService points at a Service over
// the DaemonSet. The kube-apiserver must present a client certificate from client_ca_file (the
// cluster's requestheader / front-proxy CA) unless insecure_no_client_auth is set.
type ExtMetricsConfig struct {
	APIURL               string            `json:"api_url"`
	Project              string            `json:"project"`
	APIKey               string            `json:"api_key"` // a secret reference; needs telemetry read
	Listen               string            `json:"listen"`  // default :6443
	CertFile             string            `json:"cert_file"`
	KeyFile              string            `json:"key_file"`
	ClientCAFile         string            `json:"client_ca_file"`
	InsecureNoClientAuth bool              `json:"insecure_no_client_auth"`
	Metrics              map[string]string `json:"metrics"`
}

const extGroup = "/apis/external.metrics.k8s.io/v1beta1"

var (
	extMetricName = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.-]{0,99})$`)
	promLabel     = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)
)

// ExtMetrics answers external.metrics.k8s.io requests; Query runs one instant PromQL query and
// returns (labels, value) per series.
type ExtMetrics struct {
	Metrics map[string]string
	Query   func(ctx context.Context, promql string) ([]ExtSample, error)
	Now     func() time.Time
}

// ExtSample is one series of an instant query result.
type ExtSample struct {
	Labels map[string]string
	Value  float64
}

// SelectorMatchers turns a Kubernetes label selector (equality, set and existence requirements)
// into PromQL matchers. Values are quoted for a PromQL string; keys must be label names.
func SelectorMatchers(sel string) (string, error) {
	s, err := labels.Parse(sel)
	if err != nil {
		return "", err
	}
	reqs, _ := s.Requirements()
	var out []string
	q := func(v string) string { return strconv.Quote(v) }
	for _, r := range reqs {
		k := r.Key()
		if !promLabel.MatchString(k) {
			return "", fmt.Errorf("label %q is not a metric label name", k)
		}
		vals := r.ValuesUnsorted()
		sort.Strings(vals)
		alt := make([]string, 0, len(vals))
		for _, v := range vals {
			alt = append(alt, regexp.QuoteMeta(v))
		}
		switch r.Operator() {
		case "=", "==":
			out = append(out, k+"="+q(vals[0]))
		case "!=":
			out = append(out, k+"!="+q(vals[0]))
		case "in":
			out = append(out, k+"=~"+q(strings.Join(alt, "|")))
		case "notin":
			out = append(out, k+"!~"+q(strings.Join(alt, "|")))
		case "exists":
			out = append(out, k+`!=""`)
		case "!":
			out = append(out, k+`=""`)
		default:
			return "", fmt.Errorf("selector operator %s is not supported", r.Operator())
		}
	}
	return strings.Join(out, ","), nil
}

func (e *ExtMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == extGroup {
		res := make([]map[string]any, 0, len(e.Metrics))
		names := make([]string, 0, len(e.Metrics))
		for n := range e.Metrics {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			res = append(res, map[string]any{"name": n, "singularName": "", "namespaced": true, "kind": "ExternalMetricValueList", "verbs": []string{"get"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "external.metrics.k8s.io/v1beta1", "resources": res})
		return
	}
	rest, ok := strings.CutPrefix(path, extGroup+"/namespaces/")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) != 2 {
		status(w, http.StatusNotFound, "not found")
		return
	}
	tmpl, ok := e.Metrics[parts[1]]
	if !ok {
		status(w, http.StatusNotFound, "metric "+parts[1]+" is not exposed")
		return
	}
	m, err := SelectorMatchers(r.URL.Query().Get("labelSelector"))
	if err != nil {
		status(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	samples, err := e.Query(ctx, strings.ReplaceAll(tmpl, "{{selector}}", m))
	if err != nil {
		slog.Warn("external_metrics: query failed", "metric", parts[1], "error", err)
		status(w, http.StatusServiceUnavailable, "the Watchtower query failed")
		return
	}
	items := make([]map[string]any, 0, len(samples))
	ts := e.Now().UTC().Format(time.RFC3339)
	for _, s := range samples {
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			continue
		}
		q := resource.NewMilliQuantity(int64(math.Round(s.Value*1000)), resource.DecimalSI)
		items = append(items, map[string]any{"metricName": parts[1], "metricLabels": s.Labels, "timestamp": ts, "value": q.String()})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "ExternalMetricValueList", "apiVersion": "external.metrics.k8s.io/v1beta1", "metadata": map[string]any{}, "items": items})
}

func status(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": msg, "code": code})
}

// promQuery runs an instant query through the project's Prometheus-compatible API.
func promQuery(api *ascode.Client) func(ctx context.Context, q string) ([]ExtSample, error) {
	return func(ctx context.Context, q string) ([]ExtSample, error) {
		var r struct {
			Status string `json:"status"`
			Data   struct {
				Result []struct {
					Metric map[string]string `json:"metric"`
					Value  [2]any            `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := api.Do(ctx, http.MethodGet, "prometheus/api/v1/query?query="+url.QueryEscape(q), nil, nil, &r); err != nil {
			return nil, err
		}
		out := make([]ExtSample, 0, len(r.Data.Result))
		for _, s := range r.Data.Result {
			str, _ := s.Value[1].(string)
			v, err := strconv.ParseFloat(str, 64)
			if err == nil {
				delete(s.Metric, "__name__")
				out = append(out, ExtSample{Labels: s.Metric, Value: v})
			}
		}
		return out, nil
	}
}

// RunExtMetrics serves until ctx ends.
func RunExtMetrics(ctx context.Context, raw json.RawMessage) error {
	var c ExtMetricsConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("external_metrics: %w", err)
	}
	if len(c.Metrics) == 0 || len(c.Metrics) > 100 {
		return errors.New("external_metrics: 1 to 100 metrics")
	}
	for n := range c.Metrics {
		if !extMetricName.MatchString(n) {
			return fmt.Errorf("external_metrics: %q is not a metric name (lowercase, digits, . _ -)", n)
		}
	}
	api, err := ascode.New(c.APIURL, c.APIKey, c.Project, netguard.Guarded("agent", 30*time.Second))
	if err != nil {
		return fmt.Errorf("external_metrics: %w", err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.ClientCAFile != "":
		pem, err := os.ReadFile(c.ClientCAFile)
		if err != nil {
			return fmt.Errorf("external_metrics: client_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("external_metrics: client_ca_file holds no certificate")
		}
		tc.ClientCAs, tc.ClientAuth = pool, tls.RequireAndVerifyClientCert
	case !c.InsecureNoClientAuth:
		return errors.New("external_metrics: set client_ca_file (the front-proxy CA) or insecure_no_client_auth")
	}
	listen := c.Listen
	if listen == "" {
		listen = ":6443"
	}
	srv := &http.Server{Addr: listen, Handler: &ExtMetrics{Metrics: c.Metrics, Query: promQuery(api), Now: time.Now},
		TLSConfig: tc, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServeTLS(c.CertFile, c.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("external_metrics: %w", err)
	}
	return nil
}
