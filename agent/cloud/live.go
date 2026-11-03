package cloud

// Live query (X10): answer one request from the provider instead of the stored pull data. It reuses
// the pullers' auth and parsing, keeping the points in memory. The caller reads no further than the
// row allows: a request may only narrow the row's lists. Tested against response shapes from the
// providers' public docs; never run against a real account.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxLiveWindow  = 7 * 24 * time.Hour
	maxLiveSeries  = 500
	maxLiveAWSRefs = 20 // each one is a billed GetMetricData metric
)

// ErrBadLiveQuery marks a request the caller can fix, as opposed to a provider failure.
var ErrBadLiveQuery = errors.New("bad query")

// LiveQuery narrows a row. An empty list means the row's whole list.
type LiveQuery struct {
	Metrics    []string `json:"metrics"`    // azure, gcp
	Resources  []string `json:"resources"`  // azure
	ZoneIDs    []string `json:"zone_ids"`   // cloudflare
	Namespaces []string `json:"namespaces"` // aws
	Metric     string   `json:"metric"`     // aws: one metric name
	Stat       string   `json:"stat"`       // aws: Average (default), Sum, Minimum, Maximum, SampleCount
}

// LivePoint is one value of a series.
type LivePoint struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// LiveSeries is one provider time series.
type LiveSeries struct {
	Name   string            `json:"name"`
	Attrs  map[string]string `json:"attrs"`
	Points []LivePoint       `json:"points"`
}

type liveSink struct {
	mu sync.Mutex
	by map[string]*LiveSeries
}

func (s *liveSink) Gauge(name, _ string, v float64, attrs map[string]string, at time.Time) {
	id := seriesID(name, attrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.by[id]
	if cur == nil {
		if len(s.by) >= maxLiveSeries {
			return
		}
		cur = &LiveSeries{Name: name, Attrs: attrs}
		s.by[id] = cur
	}
	cur.Points = append(cur.Points, LivePoint{at, v})
}

func (s *liveSink) Sum(string, string, float64, map[string]string, time.Time) {}

func (s *liveSink) Log(string, string, map[string]string, time.Time) {}

func (s *liveSink) result() []LiveSeries {
	out := make([]LiveSeries, 0, len(s.by))
	for _, c := range s.by {
		sort.Slice(c.Points, func(i, j int) bool { return c.Points[i].T.Before(c.Points[j].T) })
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return seriesID(out[i].Name, out[i].Attrs) < seriesID(out[j].Name, out[j].Attrs) })
	return out
}

// narrow replaces a row's list with the requested subset; anything outside the row is refused.
func narrow(cfg map[string]any, key string, want []string) error {
	if len(want) == 0 {
		return nil
	}
	have, _ := cfg[key].([]any)
	for _, w := range want {
		if !slices.Contains(have, any(w)) {
			return fmt.Errorf("%w: %s %q is not configured on this cloud pull", ErrBadLiveQuery, key, w)
		}
	}
	cfg[key] = want
	return nil
}

// Query answers q for one cloud pull. cfg comes from MergeCredential.
func Query(ctx context.Context, provider string, cfg map[string]any, q LiveQuery, from, to time.Time) ([]LiveSeries, error) {
	if !from.Before(to) || to.Sub(from) > maxLiveWindow {
		return nil, fmt.Errorf("%w: from must be before to, at most 7 days apart", ErrBadLiveQuery)
	}
	for key, want := range map[string][]string{"metrics": q.Metrics, "resources": q.Resources, "zone_ids": q.ZoneIDs, "namespaces": q.Namespaces} {
		if err := narrow(cfg, key, want); err != nil {
			return nil, err
		}
	}
	out := &liveSink{by: map[string]*LiveSeries{}}
	if provider == "aws" {
		if err := liveAWS(ctx, cfg, q.Metric, q.Stat, from, to, out); err != nil {
			return nil, err
		}
		return out.result(), nil
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, errors.New("malformed config")
	}
	p, err := newPuller(PullSpec{Provider: provider, Config: raw, PublicOnly: true})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadLiveQuery, err)
	}
	if err := p.pull(ctx, from, to, newEmitter(out, provider)); err != nil {
		return nil, err
	}
	return out.result(), nil
}

// liveAWS uses only the row's own keys: the ambient credential chain would read with the server's
// identity instead.
func liveAWS(ctx context.Context, cfg map[string]any, metric, stat string, from, to time.Time, out sink.Sink) error {
	switch stat {
	case "":
		stat = "Average"
	case "Average", "Sum", "Minimum", "Maximum", "SampleCount":
	default:
		return fmt.Errorf("%w: stat must be Average, Sum, Minimum, Maximum or SampleCount", ErrBadLiveQuery)
	}
	key, _ := cfg["access_key_id"].(string)
	secret, _ := cfg["secret_access_key"].(string)
	token, _ := cfg["session_token"].(string)
	region, _ := cfg["region"].(string)
	base, _ := cfg["endpoint"].(string)
	if key == "" || secret == "" || region == "" {
		return fmt.Errorf("%w: aws needs access_key_id, secret_access_key and region", ErrBadLiveQuery)
	}
	var namespaces []string
	switch l := cfg["namespaces"].(type) {
	case []string:
		namespaces = l
	case []any:
		for _, v := range l {
			if s, ok := v.(string); ok {
				namespaces = append(namespaces, s)
			}
		}
	}
	if len(namespaces) == 0 {
		return fmt.Errorf("%w: aws needs namespaces", ErrBadLiveQuery)
	}
	opts := cloudwatch.Options{
		Region: region, HTTPClient: tenantClient(),
		Credentials: credentials.NewStaticCredentialsProvider(key, secret, token),
	}
	if base != "" {
		opts.BaseEndpoint = aws.String(base)
	}
	period := int32(300)
	if p, ok := cfg["period_s"].(float64); ok && (p == 60 || p == 300) {
		period = int32(p)
	}
	api := sdkCW{c: cloudwatch.New(opts), period: period}
	var qs []query
	for _, ns := range namespaces {
		refs, err := api.list(ctx, ns, 500)
		if err != nil {
			return errors.New("aws list metrics failed")
		}
		for _, r := range refs {
			if (metric == "" || r.Name == metric) && len(qs) < maxLiveAWSRefs {
				qs = append(qs, query{ID: fmt.Sprintf("q%d", len(qs)), Ref: r, Stat: stat})
			}
		}
	}
	if len(qs) == 0 {
		return nil
	}
	got, err := api.series(ctx, qs, from, to)
	if err != nil {
		return errors.New("aws get metric data failed") // SDK errors quote the request
	}
	attrs := (&poller{region: region}).attrs
	for _, q := range qs {
		for _, p := range got[q.ID] {
			out.Gauge("amazonaws.com/"+q.Ref.Namespace+"/"+q.Ref.Name, "", p.Value, attrs(q), p.At)
		}
	}
	return nil
}
