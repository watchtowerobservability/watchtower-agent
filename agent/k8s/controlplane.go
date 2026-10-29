package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	dto "github.com/prometheus/client_model/go"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const maxPromBody = 32 << 20

// ControlPlaneConfig is the `controlplane` section of the cluster agent's config. The API server
// is scraped through the in-cluster service account (the ClusterRole carries `get` on the
// non-resource URL /metrics). The scheduler and controller manager are scraped only when named
// in Targets; kubeadm serves them on https :10259 and :10257 of each control-plane node
// (their bind-address must not be 127.0.0.1). etcd needs client certificates, so it is scraped
// only when EtcdClientCertSecret is set.
type ControlPlaneConfig struct {
	Enabled *bool `json:"enabled"`
	// Targets: "scheduler", "controller-manager" (resolved to the kube-system static pods) or a
	// full https URL.
	Targets []string `json:"targets"`
	// EtcdTargets: https URLs such as https://10.0.0.5:2379/metrics, or "etcd" (static pods).
	EtcdTargets []string `json:"etcd_targets"`
	// EtcdClientCertSecret is the directory the etcd client Secret is mounted at (tls.crt,
	// tls.key, ca.crt). The agent never reads Secrets through the API.
	EtcdClientCertSecret string `json:"etcd_client_cert_secret"`
	InsecureTLS          bool   `json:"insecure_tls"`
	TokenFile            string `json:"token_file"`
	CAFile               string `json:"ca_file"`
}

// ErrEtcdNeedsClientCert is returned when etcd targets are listed without a client certificate.
var ErrEtcdNeedsClientCert = errors.New("controlplane: etcd targets need etcd_client_cert_secret (tls.crt, tls.key, ca.crt)")

func (c *ControlPlaneConfig) validate() error {
	if len(c.EtcdTargets) > 0 && c.EtcdClientCertSecret == "" {
		return ErrEtcdNeedsClientCert
	}
	return nil
}

func tlsFromDir(dir string, insecure bool) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in, local config only
	if dir == "" {
		return tc, nil
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		return nil, err
	}
	tc.Certificates = []tls.Certificate{cert}
	if pem, err := os.ReadFile(filepath.Join(dir, "ca.crt")); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(pem) {
			tc.RootCAs = pool
		}
	}
	return tc, nil
}

// promClient fetches Prometheus text documents. The token file is re-read on every call
// because projected tokens rotate.
type promClient struct {
	hc        *http.Client
	tokenFile string
}

func newPromClient(tc *tls.Config, tokenFile string) *promClient {
	hc := netguard.NewClientWith(netguard.FromEnv("agent"), netguard.Options{}, func(tr *http.Transport) { tr.TLSClientConfig = tc })
	hc.Timeout = 15 * time.Second
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &promClient{tokenFile: tokenFile, hc: hc}
}

func (p *promClient) fetch(ctx context.Context, url string) (map[string]*dto.MetricFamily, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if p.tokenFile != "" {
		tok, err := os.ReadFile(p.tokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape %s: status %d", url, resp.StatusCode)
	}
	return parseProm(io.LimitReader(resp.Body, maxPromBody))
}

// emitFamilies forwards the families keep accepts under their original names, so community
// dashboards keep working. base carries the (sink.Res-prefixed) resource attributes; attrs maps
// a metric's labels to the attributes to emit.
func emitFamilies(out sink.Sink, fams map[string]*dto.MetricFamily, base map[string]string,
	keep func(string) bool, attrs func(map[string]string) map[string]string, at time.Time) {
	for name, fam := range fams {
		if !keep(name) {
			continue
		}
		for _, m := range fam.GetMetric() {
			lbl := make(map[string]string, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				lbl[l.GetName()] = l.GetValue()
			}
			a := sink.With(base)
			for k, v := range attrs(lbl) {
				a[k] = v
			}
			forwardMetric(out, fam.GetType(), name, m, a, at)
		}
	}
}

func forwardMetric(out sink.Sink, t dto.MetricType, name string, m *dto.Metric, a map[string]string, at time.Time) {
	switch t {
	case dto.MetricType_COUNTER:
		out.Sum(name, "", m.GetCounter().GetValue(), a, at)
	case dto.MetricType_GAUGE:
		out.Gauge(name, "", m.GetGauge().GetValue(), a, at)
	case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
		h := m.GetHistogram()
		for _, b := range h.GetBucket() {
			le := strconv.FormatFloat(b.GetUpperBound(), 'g', -1, 64)
			out.Sum(name+"_bucket", "", float64(b.GetCumulativeCount()), sink.With(a, "le", le), at)
		}
		out.Sum(name+"_sum", "", h.GetSampleSum(), a, at)
		out.Sum(name+"_count", "", float64(h.GetSampleCount()), a, at)
	case dto.MetricType_SUMMARY:
		s := m.GetSummary()
		for _, q := range s.GetQuantile() {
			out.Gauge(name, "", q.GetValue(), sink.With(a, "quantile", strconv.FormatFloat(q.GetQuantile(), 'g', -1, 64)), at)
		}
		out.Sum(name+"_sum", "", s.GetSampleSum(), a, at)
		out.Sum(name+"_count", "", float64(s.GetSampleCount()), a, at)
	default:
		out.Gauge(name, "", m.GetUntyped().GetValue(), a, at)
	}
}

// ControlPlane scrapes the control-plane endpoints.
type ControlPlane struct {
	cfg     ControlPlaneConfig
	apiURL  string // https://host:port of the API server
	cluster string
	api     *promClient
	etcd    *promClient
	resolve func(component string) []string // "scheduler" etc. -> metrics URLs
}

// NewControlPlane builds the scraper; it fails when etcd targets lack a client certificate.
func NewControlPlane(cfg ControlPlaneConfig, apiURL, cluster string, resolve func(string) []string) (*ControlPlane, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = filepath.Join(saDir, "token")
	}
	if cfg.CAFile == "" {
		cfg.CAFile = filepath.Join(saDir, "ca.crt")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS} //nolint:gosec // opt-in, local config only
	if pem, err := os.ReadFile(cfg.CAFile); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(pem) {
			tc.RootCAs = pool
		}
	}
	cp := &ControlPlane{cfg: cfg, apiURL: strings.TrimRight(apiURL, "/"), cluster: cluster,
		api: newPromClient(tc, cfg.TokenFile), resolve: resolve}
	if len(cfg.EtcdTargets) > 0 {
		etc, err := tlsFromDir(cfg.EtcdClientCertSecret, cfg.InsecureTLS)
		if err != nil {
			return nil, fmt.Errorf("controlplane: etcd client certificate: %w", err)
		}
		cp.etcd = newPromClient(etc, "")
	}
	return cp, nil
}

// controlPlaneLabels maps a component name to its kube-system static pod label and metrics port
// (kubeadm defaults).
var controlPlaneLabels = map[string]struct {
	label string
	port  int
}{
	"scheduler":          {"kube-scheduler", 10259},
	"controller-manager": {"kube-controller-manager", 10257},
	"etcd":               {"etcd", 2379},
}

type cpTarget struct{ component, url string }

func (c *ControlPlane) expand(names []string, fallback string) []cpTarget {
	var out []cpTarget
	for _, n := range names {
		if strings.HasPrefix(n, "https://") {
			out = append(out, cpTarget{fallback, n})
			continue
		}
		if _, ok := controlPlaneLabels[n]; !ok || c.resolve == nil {
			continue
		}
		for _, u := range c.resolve(n) {
			out = append(out, cpTarget{n, u})
		}
	}
	return out
}

// Scrape reports apiserver_*, etcd_*, scheduler_*, workqueue_* ... series under their original
// names with `component` as a point attribute, plus `up` per target. One failing target never
// stops the others.
func (c *ControlPlane) Scrape(ctx context.Context, out sink.Sink, at time.Time) {
	base := sink.Res(map[string]string{})
	if c.cluster != "" {
		base = sink.Res(map[string]string{"k8s.cluster.name": c.cluster})
	}
	one := func(pc *promClient, t cpTarget) {
		fams, err := pc.fetch(ctx, t.url)
		a := sink.With(base, "component", t.component, "instance", t.url)
		if err != nil {
			slog.Warn("control plane scrape failed", "component", t.component, "error", err)
			out.Gauge("up", "1", 0, a, at)
			return
		}
		out.Gauge("up", "1", 1, a, at)
		emitFamilies(out, fams, sink.With(base, "component", t.component), func(string) bool { return true }, sink.Strip, at)
	}
	one(c.api, cpTarget{"apiserver", c.apiURL + "/metrics"})
	for _, t := range c.expand(c.cfg.Targets, "controlplane") {
		one(c.api, t)
	}
	if c.etcd != nil {
		for _, t := range c.expand(c.cfg.EtcdTargets, "etcd") {
			one(c.etcd, t)
		}
	}
}

func runControlPlane(ctx context.Context, cp *ControlPlane, interval time.Duration, out sink.Sink) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		cp.Scrape(ctx, out, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
