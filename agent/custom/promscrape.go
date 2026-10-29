package custom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	dto "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxScrapeBody    = 10 << 20
	maxScrapeSamples = 50_000
	maxTargets       = 100
	targetsFileEvery = 30 * time.Second
	acceptHeader     = "application/openmetrics-text;version=1.0.0;q=0.6,text/plain;version=0.0.4;q=0.4"
)

// errDropped: relabel_configs removed the target; nothing is scraped and no `wt_scrape_up` is sent.
var errDropped = errors.New("target dropped by relabel_configs")

// TargetSpec is one text-exposition endpoint.
type TargetSpec struct {
	URL      string            `json:"url"`
	Interval string            `json:"interval"` // older name of scrape_interval
	Labels   map[string]string `json:"labels"`
	// ScrapeInterval is 5s to 1h (default 60s); ScrapeTimeout 1s to 1h (default 10s).
	ScrapeInterval string `json:"scrape_interval"`
	ScrapeTimeout  string `json:"scrape_timeout"`
	// HonorLabels keeps a scraped label that clashes with a target label; otherwise the target
	// label wins and the scraped one is renamed `exported_<name>` (Prometheus behavior).
	HonorLabels bool `json:"honor_labels"`
	// SampleLimit fails the whole scrape when the target exposes more samples (default 50,000).
	SampleLimit int `json:"sample_limit"`
	// RelabelConfigs run on the target labels before the scrape (`__address__`, `__scheme__`,
	// `__metrics_path__` and the configured labels); MetricRelabelConfigs on every sample after
	// it (`__name__` is the metric name).
	RelabelConfigs       []RelabelRule `json:"relabel_configs"`
	MetricRelabelConfigs []RelabelRule `json:"metric_relabel_configs"`
}

// PromConfig is the module config. TargetsFile and TextfileDir name local paths, so only the
// agent's own config file may set them, never remote config.
type PromConfig struct {
	Targets []TargetSpec `json:"targets"`
	// TargetsFile is a JSON or YAML file in Prometheus file_sd form
	// (`[{"targets": ["host:port"], "labels": {...}}]`), re-read every 30 s.
	TargetsFile string `json:"targets_file"`
	// TextfileDir holds `*.prom` files in exposition format (the textfile collector).
	TextfileDir string `json:"textfile_dir"`
	// SDConfigs discover targets (http, dns, consul, ec2; see promsd.go), local config only.
	SDConfigs []SDConfig `json:"sd_configs"`
	// ShardTotal and ShardIndex split every target (static, file and discovered) across agents
	// sharing one config: this agent scrapes the targets whose md5(url) mod ShardTotal is ShardIndex.
	ShardTotal int `json:"shard_total"`
	ShardIndex int `json:"shard_index"`
}

// Prometheus scrapes targets and forwards them as OTLP samples.
type Prometheus struct {
	// Allow lists the host:port values a remote-origin config may scrape. Targets in the agent's
	// own config file are always allowed. Empty means remote config can add no targets.
	Allow  []string
	Client *http.Client
}

// Overlay adds the targets of a remote-origin config to the local ones, after checking each
// against the allow list. Remote config cannot remove or change a local target.
func (p Prometheus) Overlay(local, remote json.RawMessage) (json.RawMessage, error) {
	var lc, rc PromConfig
	if len(local) > 0 {
		if err := json.Unmarshal(local, &lc); err != nil {
			return nil, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(remote))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rc); err != nil {
		return nil, err
	}
	if len(lc.Targets)+len(rc.Targets) > maxTargets {
		return nil, fmt.Errorf("at most %d scrape targets", maxTargets)
	}
	if rc.TargetsFile != "" || rc.TextfileDir != "" || len(rc.SDConfigs) > 0 || rc.ShardTotal != 0 {
		return nil, errors.New("targets_file, textfile_dir, sd_configs and shard_total can only be set in the agent's own config file")
	}
	for _, t := range rc.Targets {
		if len(t.RelabelConfigs) > 0 {
			// relabeling can rewrite __address__ and so step around scrape_allow
			return nil, errors.New("relabel_configs can only be set in the agent's own config file")
		}
		if err := ValidateRelabel(t.MetricRelabelConfigs); err != nil {
			return nil, err
		}
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return nil, fmt.Errorf("scrape target %q is not a plain http(s) URL", t.URL)
		}
		if !contains(p.Allow, u.Host) {
			return nil, fmt.Errorf("scrape target host %q is not in scrape_allow", u.Host)
		}
	}
	lc.Targets = append(lc.Targets, rc.Targets...)
	return json.Marshal(lc)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// resolve applies relabel_configs. It returns the URL to fetch and the target labels (without
// `__` labels); errDropped when a keep or drop rule removed the target.
func resolve(spec TargetSpec) (string, map[string]string, error) {
	if len(spec.RelabelConfigs) == 0 {
		return spec.URL, spec.Labels, nil
	}
	u, err := url.Parse(spec.URL)
	if err != nil {
		return "", nil, err
	}
	in := map[string]string{"__address__": u.Host, "__scheme__": u.Scheme, "__metrics_path__": u.Path}
	for k, v := range spec.Labels {
		in[k] = v
	}
	out, keep := Relabel(in, spec.RelabelConfigs)
	if !keep {
		return "", nil, errDropped
	}
	u.Host, u.Scheme, u.Path = out["__address__"], out["__scheme__"], out["__metrics_path__"]
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", nil, fmt.Errorf("relabeled target %q is not an http(s) address", u.String())
	}
	labels := map[string]string{}
	for k, v := range out {
		if !strings.HasPrefix(k, "__") {
			labels[k] = v
		}
	}
	return u.String(), labels, nil
}

// batch holds one scrape's samples until the sample limit has been checked.
type batch struct {
	pts    []point
	rules  []RelabelRule
	mlabel map[string]string // labels of the metric being forwarded, for exemplar lookup
	exs    map[string]exemplar
}

type point struct {
	sum   bool
	name  string
	value float64
	attrs map[string]string
	at    time.Time
}

func (b *batch) add(sum bool, name string, v float64, a map[string]string, at time.Time) {
	if len(b.rules) > 0 {
		in := with(a, "__name__", name)
		out, keep := Relabel(in, b.rules)
		if !keep {
			return
		}
		name = out["__name__"]
		delete(out, "__name__")
		a = out
		if name == "" {
			return
		}
	}
	if b.exs != nil {
		le := ""
		if strings.HasSuffix(name, "_bucket") {
			le = a["le"]
		}
		if ex, ok := b.exs[exemplarKey(name, b.mlabel, le)]; ok {
			a = with(a, "wt.exemplar.value", ex.value)
			for k, v := range ex.labels {
				a["wt.exemplar."+k] = v
			}
		}
	}
	b.pts = append(b.pts, point{sum, name, v, a, at})
}

func (b *batch) Gauge(n, _ string, v float64, a map[string]string, at time.Time) {
	b.add(false, n, v, a, at)
}

func (b *batch) Sum(n, _ string, v float64, a map[string]string, at time.Time) {
	b.add(true, n, v, a, at)
}

// Scrape fetches one target and writes its samples to out. Counters become cumulative sums,
// gauges and untyped values gauges. A histogram becomes `<name>_bucket{le}`, `<name>_sum` and
// `<name>_count`; a summary `<name>{quantile}`, `<name>_sum` and `<name>_count` (the Prometheus
// naming, so existing queries port). The target may answer in OpenMetrics, whose exemplars
// become `wt.exemplar.*` attributes on the sample. A target over sample_limit fails the scrape
// and emits nothing.
func (p Prometheus) Scrape(ctx context.Context, spec TargetSpec, out Sink, now time.Time) error {
	target, tlabels, err := resolve(spec)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, parseDur(spec.ScrapeTimeout, 10*time.Second, time.Second, time.Hour))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", acceptHeader)
	client := p.Client
	if client == nil {
		// no redirects: they would step around the scrape_allow check
		client = netguard.GuardedNoRedirect("agent", 0)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scrape %s: status %d", target, resp.StatusCode)
	}
	var body io.Reader = io.LimitReader(resp.Body, maxScrapeBody)
	var exs map[string]exemplar
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/openmetrics-text") {
		raw, err := io.ReadAll(body)
		if err != nil {
			return fmt.Errorf("scrape %s: %w", target, err)
		}
		var text string
		text, exs = omToText(string(raw))
		body = strings.NewReader(text)
	}
	fams, err := parseProm(body)
	if err != nil {
		return fmt.Errorf("scrape %s: %w", target, err)
	}
	limit := maxScrapeSamples
	if spec.SampleLimit > 0 {
		limit = spec.SampleLimit
	}
	b := &batch{rules: spec.MetricRelabelConfigs, exs: exs}
	emit := func(f func(string, string, float64, map[string]string, time.Time), name string, v float64, attrs map[string]string, at time.Time) {
		if !math.IsNaN(v) {
			f(name, "", v, attrs, at)
		}
	}
	for name, fam := range fams {
		for _, m := range fam.GetMetric() {
			attrs := make(map[string]string, len(tlabels)+len(m.GetLabel()))
			for k, v := range tlabels {
				attrs[k] = v
			}
			b.mlabel = make(map[string]string, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				b.mlabel[l.GetName()] = l.GetValue()
				k := l.GetName()
				if _, clash := tlabels[k]; clash && !spec.HonorLabels {
					k = "exported_" + k
				}
				attrs[k] = l.GetValue()
			}
			attrs = sink.Strip(attrs) // a scraped label must never name the OTLP resource
			at := now
			if ts := m.GetTimestampMs(); ts > 0 {
				at = time.UnixMilli(ts)
			}
			forward(fam.GetType(), name, m, attrs, at, b, emit)
		}
	}
	if len(b.pts) > limit {
		return fmt.Errorf("scrape %s: %d samples exceed sample_limit %d", target, len(b.pts), limit)
	}
	for _, s := range b.pts {
		if s.sum {
			out.Sum(s.name, "", s.value, s.attrs, s.at)
		} else {
			out.Gauge(s.name, "", s.value, s.attrs, s.at)
		}
	}
	return nil
}

type emitFn = func(f func(string, string, float64, map[string]string, time.Time), name string, v float64, attrs map[string]string, at time.Time)

func with(attrs map[string]string, k, v string) map[string]string {
	c := make(map[string]string, len(attrs)+1)
	for a, b := range attrs {
		c[a] = b
	}
	c[k] = v
	return c
}

func forward(t dto.MetricType, name string, m *dto.Metric, attrs map[string]string, at time.Time, out Sink, emit emitFn) {
	switch t {
	case dto.MetricType_COUNTER:
		emit(out.Sum, name, m.GetCounter().GetValue(), attrs, at)
	case dto.MetricType_GAUGE:
		emit(out.Gauge, name, m.GetGauge().GetValue(), attrs, at)
	case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
		h := m.GetHistogram()
		for _, b := range h.GetBucket() {
			le := strconv.FormatFloat(b.GetUpperBound(), 'g', -1, 64)
			emit(out.Sum, name+"_bucket", float64(b.GetCumulativeCount()), with(attrs, "le", le), at)
		}
		emit(out.Sum, name+"_sum", h.GetSampleSum(), attrs, at)
		emit(out.Sum, name+"_count", float64(h.GetSampleCount()), attrs, at)
	case dto.MetricType_SUMMARY:
		s := m.GetSummary()
		for _, q := range s.GetQuantile() {
			emit(out.Gauge, name, q.GetValue(), with(attrs, "quantile", strconv.FormatFloat(q.GetQuantile(), 'g', -1, 64)), at)
		}
		emit(out.Sum, name+"_sum", s.GetSampleSum(), attrs, at)
		emit(out.Sum, name+"_count", float64(s.GetSampleCount()), attrs, at)
	default:
		emit(out.Gauge, name, m.GetUntyped().GetValue(), attrs, at)
	}
}

// Run scrapes every target on its interval until ctx ends. A failed scrape is reported through
// `up{job}`-style gauge `wt_scrape_up` (1 or 0), never as a crash.
func (p Prometheus) Run(ctx context.Context, raw json.RawMessage, out Sink) error {
	var c PromConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if len(c.Targets) > maxTargets {
		return fmt.Errorf("at most %d scrape targets", maxTargets)
	}
	if c.ShardTotal < 0 || (c.ShardTotal > 0 && (c.ShardIndex < 0 || c.ShardIndex >= c.ShardTotal)) {
		return errors.New("shard_index must be in [0, shard_total)")
	}
	if err := p.startSD(ctx, c, out); err != nil {
		return err
	}
	for _, spec := range c.Targets {
		if !inShard(spec.URL, c.ShardTotal, c.ShardIndex) {
			continue
		}
		if err := ValidateRelabel(append(append([]RelabelRule(nil), spec.RelabelConfigs...), spec.MetricRelabelConfigs...)); err != nil {
			return fmt.Errorf("scrape target %s: %w", redact(spec.URL), err)
		}
		go p.loop(ctx, spec, out)
	}
	if c.TargetsFile != "" {
		go p.watchFile(ctx, c.TargetsFile, len(c.Targets), c.ShardTotal, c.ShardIndex, out)
	}
	if c.TextfileDir != "" {
		go func() {
			t := time.NewTicker(defaultInterval)
			defer t.Stop()
			for {
				ReadTextfiles(c.TextfileDir, out, time.Now())
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
	<-ctx.Done()
	return nil
}

type fileGroup struct {
	Targets []string          `yaml:"targets"`
	Labels  map[string]string `yaml:"labels"`
}

// readTargetsFile parses a file_sd file (JSON is YAML) into specs; a bare host:port becomes
// http://host:port/metrics.
func readTargetsFile(path string) ([]TargetSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var groups []fileGroup
	if err := yaml.Unmarshal(b, &groups); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return groupSpecs(groups), nil
}

// groupSpecs turns file_sd / http_sd groups into specs.
func groupSpecs(groups []fileGroup) []TargetSpec {
	var out []TargetSpec
	for _, g := range groups {
		for _, t := range g.Targets {
			u := t
			if !strings.Contains(u, "://") {
				u = "http://" + u + "/metrics"
			}
			out = append(out, TargetSpec{URL: u, Labels: g.Labels})
		}
	}
	return out
}

// watchFile re-reads the targets file every 30 s: new targets start, removed ones stop with a
// staleness marker. A file that cannot be read or parsed keeps the targets already running.
func (p Prometheus) watchFile(ctx context.Context, path string, fixed, total, index int, out Sink) {
	p.watchSource(ctx, targetsFileEvery, fixed, total, index, func(context.Context) ([]TargetSpec, error) {
		return readTargetsFile(path)
	}, out)
}

func (p Prometheus) loop(ctx context.Context, spec TargetSpec, out Sink) {
	iv := spec.ScrapeInterval
	if iv == "" {
		iv = spec.Interval
	}
	t := time.NewTicker(parseDur(iv, defaultInterval, minInterval, time.Hour))
	defer t.Stop()
	wasDown := false
	for {
		now := time.Now()
		up := 1.0
		if err := p.Scrape(ctx, spec, out, now); err != nil {
			if errors.Is(err, errDropped) || ctx.Err() != nil {
				return
			}
			up = 0
		}
		lbl := map[string]string{"target": redact(spec.URL)}
		out.Gauge("wt_scrape_up", "", up, lbl, now)
		if up == 0 || wasDown {
			// a failing target's series have ended; the 0 sent on recovery lets queries resume the line
			out.Gauge("wt_scrape_stale", "", 1-up, lbl, now)
		}
		wasDown = up == 0
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// redact drops the query and user info of a target URL before it becomes a label.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return strings.TrimSpace(u.String())
}
