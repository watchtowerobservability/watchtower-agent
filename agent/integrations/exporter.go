package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// ExporterConfig is the config of every module that reads a product's Prometheus text endpoint:
// the product's own (consul, vault, pulsar, ceph) or a well-known exporter next to it (mssql,
// oracle, cassandra, windows, kinesis). URL, Token and the password exist only in the agent's file.
type ExporterConfig struct {
	Base
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
	// Prefixes narrows the scrape to metric names starting with one of them (a module has a default).
	Prefixes []string `json:"prefixes"`
}

func (c *ExporterConfig) check() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("url (http or https) is required (in the agent's own config file)")
	}
	return nil
}

// exporterSpec is what differs between the modules.
type exporterSpec struct {
	name     string
	prefixes []string // default Prefixes
	path     string   // appended when url has no path, e.g. /v1/sys/metrics?format=prometheus
	header   string   // header that carries Token; empty means Authorization: Bearer
	interval time.Duration
	rename   string // prepended to forwarded names that lack it (products whose names are unprefixed)
	basic    bool   // the product only takes basic auth, so Username wins over Token
}

const maxSeries = 5000 // per scrape; a runaway exporter is cut here, not allowed to flood the pipeline

// runExporter is the module body shared by the scrape-based integrations.
func runExporter(ctx context.Context, sp exporterSpec, raw json.RawMessage, out sink.Sink) error {
	c := &ExporterConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if len(c.Prefixes) == 0 {
		c.Prefixes = sp.prefixes
	}
	target := c.URL
	if u, _ := url.Parse(c.URL); u.Path == "" || u.Path == "/" {
		target = strings.TrimRight(c.URL, "/") + sp.path
	}
	return Loop(ctx, sp.name, c.Base, sp.interval, out, func(ctx context.Context, now time.Time) error {
		return scrapeOne(ctx, sp, c, target, out, now)
	})
}

// scrapeOne reads one Prometheus text endpoint and forwards the families of c.Prefixes.
func scrapeOne(ctx context.Context, sp exporterSpec, c *ExporterConfig, target string, out sink.Sink, now time.Time) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/plain;version=0.0.4")
	authorize(req, sp, c)
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.New(sink.Truncate(err.Error(), 200)) // the URL may carry a token
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", sp.name, resp.StatusCode)
	}
	tp := expfmt.NewTextParser(model.UTF8Validation)
	fams, err := tp.TextToMetricFamilies(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%s: not Prometheus text: %w", sp.name, err)
	}
	prefixes := c.Prefixes
	if sp.rename != "" {
		fams, prefixes = withPrefix(fams, prefixes, sp.rename), nil
	}
	EmitFamilies(out, fams, prefixes, now)
	return nil
}

// withPrefix keeps the families matching prefixes and names each p+name unless it starts with p.
func withPrefix(fams map[string]*dto.MetricFamily, prefixes []string, p string) map[string]*dto.MetricFamily {
	out := make(map[string]*dto.MetricFamily, len(fams))
	for n, f := range fams {
		if !hasPrefix(n, prefixes) {
			continue
		}
		if !strings.HasPrefix(n, p) {
			n = p + n
		}
		out[n] = f
	}
	return out
}

func authorize(req *http.Request, sp exporterSpec, c *ExporterConfig) {
	switch {
	case sp.basic && c.Username != "":
		req.SetBasicAuth(c.Username, c.Password)
	case c.Token != "" && sp.header != "":
		req.Header.Set(sp.header, c.Token)
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case c.Username != "":
		req.SetBasicAuth(c.Username, c.Password)
	}
}

func hasPrefix(name string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// EmitFamilies forwards the families whose name starts with one of prefixes: counters as sums,
// gauges and untyped as gauges, histograms and summaries as their _count and _sum. It stops
// after maxSeries points.
func EmitFamilies(out sink.Sink, fams map[string]*dto.MetricFamily, prefixes []string, at time.Time) {
	n := 0
	for name, f := range fams {
		if !hasPrefix(name, prefixes) {
			continue
		}
		for _, m := range f.GetMetric() {
			if n++; n > maxSeries {
				return
			}
			a := map[string]string{}
			for _, l := range m.GetLabel() {
				a[l.GetName()] = l.GetValue()
			}
			switch f.GetType() {
			case dto.MetricType_COUNTER:
				out.Sum(name, "1", m.GetCounter().GetValue(), a, at)
			case dto.MetricType_GAUGE:
				out.Gauge(name, "1", m.GetGauge().GetValue(), a, at)
			case dto.MetricType_UNTYPED:
				out.Gauge(name, "1", m.GetUntyped().GetValue(), a, at)
			case dto.MetricType_SUMMARY:
				out.Sum(name+"_count", "1", float64(m.GetSummary().GetSampleCount()), a, at)
				out.Sum(name+"_sum", "1", m.GetSummary().GetSampleSum(), a, at)
			case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
				out.Sum(name+"_count", "1", float64(m.GetHistogram().GetSampleCount()), a, at)
				out.Sum(name+"_sum", "1", m.GetHistogram().GetSampleSum(), a, at)
			}
		}
	}
}

// Oracle scrapes oracledb_exporter.
func Oracle(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "oracle", prefixes: []string{"oracledb_"}, interval: 30 * time.Second}, raw, out)
}

// Cassandra scrapes the cassandra-exporter or the JMX exporter agent.
func Cassandra(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "cassandra", prefixes: []string{"cassandra_"}, interval: 30 * time.Second}, raw, out)
}

// Consul reads the agent's own Prometheus endpoint (telemetry.prometheus_retention_time > 0).
func Consul(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "consul", prefixes: []string{"consul_"},
		path: "/v1/agent/metrics?format=prometheus", header: "X-Consul-Token", interval: 30 * time.Second}, raw, out)
}

// Vault reads /v1/sys/metrics; Token is a Vault token with read on sys/metrics.
func Vault(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "vault", prefixes: []string{"vault_"},
		path: "/v1/sys/metrics?format=prometheus", header: "X-Vault-Token", interval: 30 * time.Second}, raw, out)
}

// Windows scrapes windows_exporter: perf counters, services, IIS and (for Hyper-V) hyperv.
func Windows(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "windows", prefixes: []string{"windows_"}, interval: 30 * time.Second}, raw, out)
}

// Ceph scrapes the manager's prometheus module (port 9283).
func Ceph(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "ceph", prefixes: []string{"ceph_"}, interval: 30 * time.Second}, raw, out)
}

// Kinesis scrapes a CloudWatch exporter (YACE or cloudwatch_exporter) configured for AWS/Kinesis.
func Kinesis(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "kinesis", prefixes: []string{"aws_kinesis_"}, interval: 60 * time.Second}, raw, out)
}

// HyperV reads the Hyper-V collector of windows_exporter (VMs, vCPU, memory, switches).
func HyperV(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "hyperv", prefixes: []string{"windows_hyperv_"}, interval: 30 * time.Second}, raw, out)
}

// Pulsar reads the broker's /metrics: per-topic backlog, rates and subscriptions (queue topology).
func Pulsar(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "pulsar", prefixes: []string{"pulsar_"}, path: "/metrics", interval: 30 * time.Second}, raw, out)
}
