// Package cloud collects from public clouds: an AWS CloudWatch GetMetricData poller, the AWS
// Resource Groups Tagging API as inventory, and an Azure Event Hubs consumer (Kafka endpoint).
//
// Credentials never travel through remote config. AWS uses the SDK's standard chain (environment,
// shared credentials file, instance role); Azure's connection string is in the local file or an
// environment variable. Neither is logged, exported or put into a label or an error.
//
// shortcut: GCP and Azure API pollers are known gap G-21; GCP arrives by Pub/Sub push, Azure by
// Event Hubs.
package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// AWSConfig is the module's local configuration.
type AWSConfig struct {
	Enabled  *bool  `json:"enabled"`
	Interval string `json:"interval"` // poll interval, default = period_s, floor 60s
	Region   string `json:"region"`
	Profile  string `json:"profile"`  // shared-config profile; empty = default chain
	Endpoint string `json:"endpoint"` // override (VPC endpoint, test double)
	// Namespaces to poll, e.g. ["AWS/Lambda", "AWS/EC2"], or ["auto"] for every AWS/* namespace with
	// recent metrics. Empty = no metric polling.
	Namespaces []string `json:"namespaces"`
	MaxMetrics int      `json:"max_metrics"` // per namespace, default 100
	// Stats to request per metric (default ["Average"]). Each stat doubles the metrics billed.
	Stats []string `json:"stats"`
	// PeriodS is the GetMetricData period: 300 (default, standard resolution) or 60.
	PeriodS int `json:"period_s"`
	// Inventory turns on the Resource Groups Tagging API walk (entities of kind cloud).
	Inventory         *bool  `json:"inventory"`
	InventoryInterval string `json:"inventory_interval"` // default 5m, floor 1m
	// TagFilters polls only metrics of resources carrying every listed tag (key -> allowed values;
	// an empty list means the key must exist). CloudWatch metrics have no tags, so the tagged
	// resource ids come from the Resource Groups Tagging API and are matched against dimension values.
	TagFilters map[string][]string `json:"tag_filters"`
	// RoleARN is assumed on top of the default chain (cross-account access); ExternalID guards it.
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id"`
}

const (
	callTimeout   = 40 * time.Second
	metricsPerGet = 500              // GetMetricData limit; two queries (Average, Sum) per metric
	listCacheTTL  = 15 * time.Minute // ListMetrics is re-run at most this often per namespace
	cwLag         = 2 * time.Minute  // CloudWatch fills a bucket for a while; never read the newest minutes
)

type dim struct{ Name, Value string }

type metricRef struct {
	Namespace, Name string
	Dims            []dim
}

type query struct {
	ID   string
	Ref  metricRef
	Stat string
}

type point struct {
	At    time.Time
	Value float64
}

// cwAPI is the slice of CloudWatch the poller needs (so tests can stand in for AWS).
type cwAPI interface {
	list(ctx context.Context, namespace string, max int) ([]metricRef, error)
	// get returns the latest datapoint of each query that has one, by query id.
	get(ctx context.Context, qs []query, start, end time.Time) (map[string]point, error)
}

type sdkCW struct {
	c      *cloudwatch.Client
	period int32
}

func (s sdkCW) list(ctx context.Context, ns string, max int) ([]metricRef, error) {
	var out []metricRef
	p := cloudwatch.NewListMetricsPaginator(s.c, &cloudwatch.ListMetricsInput{Namespace: aws.String(ns)})
	for p.HasMorePages() && len(out) < max {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, m := range page.Metrics {
			r := metricRef{Namespace: aws.ToString(m.Namespace), Name: aws.ToString(m.MetricName)}
			for _, d := range m.Dimensions {
				r.Dims = append(r.Dims, dim{aws.ToString(d.Name), aws.ToString(d.Value)})
			}
			if out = append(out, r); len(out) >= max {
				break
			}
		}
	}
	return out, nil
}

func (s sdkCW) input(qs []query, start, end time.Time) *cloudwatch.GetMetricDataInput {
	in := &cloudwatch.GetMetricDataInput{StartTime: &start, EndTime: &end, ScanBy: cwtypes.ScanByTimestampDescending}
	for _, q := range qs {
		m := &cwtypes.Metric{Namespace: aws.String(q.Ref.Namespace), MetricName: aws.String(q.Ref.Name)}
		for _, d := range q.Ref.Dims {
			m.Dimensions = append(m.Dimensions, cwtypes.Dimension{Name: aws.String(d.Name), Value: aws.String(d.Value)})
		}
		in.MetricDataQueries = append(in.MetricDataQueries, cwtypes.MetricDataQuery{
			Id:         aws.String(q.ID),
			MetricStat: &cwtypes.MetricStat{Metric: m, Period: aws.Int32(s.period), Stat: aws.String(q.Stat)},
		})
	}
	return in
}

// series returns every point in the window, unlike get, which keeps the newest.
func (s sdkCW) series(ctx context.Context, qs []query, start, end time.Time) (map[string][]point, error) {
	out := map[string][]point{}
	p := cloudwatch.NewGetMetricDataPaginator(s.c, s.input(qs, start, end))
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, r := range page.MetricDataResults {
			id := aws.ToString(r.Id)
			for i := range min(len(r.Values), len(r.Timestamps)) {
				out[id] = append(out[id], point{r.Timestamps[i], r.Values[i]})
			}
		}
	}
	return out, nil
}

func (s sdkCW) get(ctx context.Context, qs []query, start, end time.Time) (map[string]point, error) {
	in := s.input(qs, start, end)
	out := map[string]point{}
	p := cloudwatch.NewGetMetricDataPaginator(s.c, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		for _, r := range page.MetricDataResults {
			id := aws.ToString(r.Id)
			if _, seen := out[id]; !seen && len(r.Values) > 0 && len(r.Timestamps) > 0 {
				out[id] = point{r.Timestamps[0], r.Values[0]}
			}
		}
	}
	return out, nil
}

// poller keeps the timestamp last emitted per series so a quiet metric is not re-sent every poll.
type poller struct {
	api    cwAPI
	region string
	max    int
	stats  []string
	period time.Duration

	mu       sync.Mutex
	last     map[string]time.Time
	listed   map[string]listing
	tags     *tagIndex // nil: no tag filter
	requests float64   // GetMetricData metric-requests so far (what CloudWatch bills), a counter
}

type listing struct {
	refs []metricRef
	exp  time.Time
}

// refs returns the namespace's metrics, listing at most every listCacheTTL.
func (p *poller) refs(ctx context.Context, ns string, now time.Time) []metricRef {
	p.mu.Lock()
	l, ok := p.listed[ns]
	p.mu.Unlock()
	if ok && now.Before(l.exp) {
		return l.refs
	}
	refs, err := p.api.list(ctx, ns, p.max) // a partial listing is still polled
	host.Warn("aws list "+ns, err)
	if len(refs) > 0 || err == nil {
		p.mu.Lock()
		p.listed[ns] = listing{refs, now.Add(listCacheTTL)}
		p.mu.Unlock()
	}
	return refs
}

func seriesKey(r metricRef, stat string) string {
	var b strings.Builder
	b.WriteString(r.Namespace + "|" + r.Name + "|" + stat)
	for _, d := range r.Dims {
		b.WriteString("|" + d.Name + "=" + d.Value)
	}
	return b.String()
}

// pollNamespaces queries every namespace concurrently, each under its own timeout, so one slow or
// failing namespace does not hold the others up.
func (p *poller) pollNamespaces(ctx context.Context, namespaces []string, out sink.Sink, now time.Time) {
	var wg sync.WaitGroup
	for _, ns := range namespaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			p.pollNamespace(cctx, ns, out, now)
		}()
	}
	wg.Wait()
	p.mu.Lock()
	n := p.requests
	p.mu.Unlock()
	out.Sum("wt_agent_cloudwatch_metric_requests", "{metric}", n, map[string]string{"cloud.region": p.region}, now)
}

func (p *poller) pollNamespace(ctx context.Context, ns string, out sink.Sink, now time.Time) {
	refs := p.tags.filter(ctx, p.refs(ctx, ns, now), now)
	var qs []query
	for _, r := range refs {
		for _, stat := range p.stats {
			qs = append(qs, query{ID: fmt.Sprintf("q%d", len(qs)), Ref: r, Stat: stat})
		}
	}
	for len(qs) > 0 {
		n := min(len(qs), metricsPerGet)
		batch := qs[:n]
		qs = qs[n:]
		end := now.Add(-cwLag)
		got, err := p.api.get(ctx, batch, end.Add(-max(10*time.Minute, 2*p.period)), end)
		host.Warn("aws get "+ns, err)
		p.mu.Lock()
		p.requests += float64(len(batch))
		p.mu.Unlock()
		for _, q := range batch {
			pt, ok := got[q.ID]
			if !ok {
				continue
			}
			k := seriesKey(q.Ref, q.Stat)
			p.mu.Lock()
			fresh := pt.At.After(p.last[k])
			if fresh {
				p.last[k] = pt.At
			}
			p.mu.Unlock()
			if fresh {
				p.evict(now)
				out.Gauge("amazonaws.com/"+q.Ref.Namespace+"/"+q.Ref.Name, "", pt.Value, p.attrs(q), pt.At)
			}
		}
	}
}

// evict bounds the dedupe map: series not seen for a day go once it passes 50k entries.
func (p *poller) evict(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.last) < 50_000 {
		return
	}
	for k, t := range p.last {
		if now.Sub(t) > 24*time.Hour {
			delete(p.last, k)
		}
	}
}

func (p *poller) attrs(q query) map[string]string {
	a := map[string]string{
		"cloud.provider": "aws", "cloud.region": p.region,
		"aws.namespace": q.Ref.Namespace, "aws.cloudwatch.stat": q.Stat,
	}
	for _, d := range q.Ref.Dims {
		a["aws.dim."+d.Name] = d.Value
	}
	return a
}

// RunAWS polls CloudWatch and walks the tagged-resource inventory until ctx ends.
func RunAWS(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runAWS(ctx, raw, out, nil)
}

func runAWS(ctx context.Context, raw json.RawMessage, out sink.Sink, hc *http.Client) error {
	var c AWSConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	inventory := c.Inventory != nil && *c.Inventory
	if c.Enabled != nil && !*c.Enabled || len(c.Namespaces) == 0 && !inventory {
		<-ctx.Done()
		return nil
	}
	sort.Strings(c.Namespaces)
	opts := []func(*awsconfig.LoadOptions) error{}
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	if c.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(c.Profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	if hc != nil {
		cfg.HTTPClient = hc
	}
	assumeRole(&cfg, c.RoleARN, c.ExternalID)
	out = sink.Hoist(out)
	var wg sync.WaitGroup
	if len(c.Namespaces) > 0 {
		cw := cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) {
			if c.Endpoint != "" {
				o.BaseEndpoint = aws.String(c.Endpoint)
			}
		})
		period := 300
		if c.PeriodS == 60 || c.PeriodS > 60 && c.PeriodS%60 == 0 {
			period = c.PeriodS
		}
		p := &poller{
			api: sdkCW{c: cw, period: int32(period)}, region: cfg.Region, max: c.MaxMetrics, //nolint:gosec // small
			stats: c.Stats, period: time.Duration(period) * time.Second,
			last: map[string]time.Time{}, listed: map[string]listing{},
		}
		if p.max <= 0 {
			p.max = 100
		}
		if len(c.TagFilters) > 0 {
			rg := resourcegroupstaggingapi.NewFromConfig(cfg, func(o *resourcegroupstaggingapi.Options) {
				if c.Endpoint != "" {
					o.BaseEndpoint = aws.String(c.Endpoint)
				}
			})
			p.tags = &tagIndex{load: func(ctx context.Context) ([]Tagged, error) { return listTaggedBy(ctx, rg, c.TagFilters) }}
		}
		if len(p.stats) == 0 {
			p.stats = []string{"Average"}
		}
		var disc *nsDiscovery
		if isAuto(c.Namespaces) {
			disc = &nsDiscovery{cw: cw}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			host.Every(ctx, host.Duration(c.Interval, p.period, 60*time.Second), func(ctx context.Context) {
				ns, now := c.Namespaces, time.Now()
				if disc != nil {
					ns = disc.namespaces(ctx, now)
				}
				p.pollNamespaces(ctx, ns, out, now)
			})
		}()
	}
	if inventory {
		rg := resourcegroupstaggingapi.NewFromConfig(cfg, func(o *resourcegroupstaggingapi.Options) {
			if c.Endpoint != "" {
				o.BaseEndpoint = aws.String(c.Endpoint)
			}
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			host.Every(ctx, host.Duration(c.InventoryInterval, 5*time.Minute, time.Minute), func(ctx context.Context) {
				cctx, cancel := context.WithTimeout(ctx, 2*callTimeout)
				defer cancel()
				rs, err := listTagged(cctx, rg) // partial inventory is still emitted
				host.Warn("aws inventory", err)
				EmitInventory(out, rs, time.Now())
			})
		}()
	}
	wg.Wait()
	return nil
}
