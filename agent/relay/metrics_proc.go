package relay

// Metric processors of the relay (CFT-A12, otelcol cumulativetodelta, deltatocumulative,
// metric_start_time, groupbyattrs and interval parity). They keep per-series state in memory,
// so a series must always reach the same relay (one relay, or senders pinned to one); state is
// cleared past 100,000 series. Stages run in order:
//
//	cumulative_to_delta  monotonic cumulative sums and histograms become deltas; the first
//	                     point of a series only primes the state and is dropped
//	delta_to_cumulative  delta sums and histograms are accumulated into cumulative ones
//	metric_start_time    cumulative points without a start time get the series' first-seen time
//	group_by_attrs       the listed point attributes move to the resource (keys)
//	interval             at most one point per series per `every` (gauges and cumulative sums)

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

const maxSeries = 100_000

// MetricStage is one metric processor.
type MetricStage struct {
	Type  string   `json:"type" yaml:"type"`
	Keys  []string `json:"keys,omitempty" yaml:"keys"`   // group_by_attrs
	Every string   `json:"every,omitempty" yaml:"every"` // interval, default 60s
}

type seriesState struct {
	t       uint64    // last time (unix ns)
	start   uint64    // first-seen / start time
	sum     float64   // sums
	count   uint64    // histograms
	hsum    float64   // histograms
	buckets []uint64  // histograms
	emitted time.Time // interval
}

// MetricProcessors is a compiled, stateful stage list (safe for concurrent use).
type MetricProcessors struct {
	stages []MetricStage
	every  []time.Duration
	mu     sync.Mutex
	state  []map[string]*seriesState // one map per stage
	now    func() time.Time
}

// CompileMetrics validates the stages.
func CompileMetrics(st []MetricStage) (*MetricProcessors, error) {
	p := &MetricProcessors{stages: st, now: time.Now}
	for i, s := range st {
		d := time.Duration(0)
		switch s.Type {
		case "cumulative_to_delta", "delta_to_cumulative", "metric_start_time":
		case "group_by_attrs":
			if len(s.Keys) == 0 {
				return nil, fmt.Errorf("metric stage %d: group_by_attrs needs keys", i)
			}
		case "interval":
			d = time.Minute
			if s.Every != "" {
				var err error
				if d, err = time.ParseDuration(s.Every); err != nil || d < time.Second {
					return nil, fmt.Errorf("metric stage %d: every must be a duration of at least 1s", i)
				}
			}
		default:
			return nil, fmt.Errorf("metric stage %d: unknown type %q", i, s.Type)
		}
		p.every = append(p.every, d)
		p.state = append(p.state, map[string]*seriesState{})
	}
	if len(st) > 16 {
		return nil, errors.New("at most 16 metric stages")
	}
	return p, nil
}

func attrKey(kvs []*commonpb.KeyValue) string {
	parts := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		parts = append(parts, kv.GetKey()+"="+kv.GetValue().String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

// Apply runs every stage on req in place.
func (p *MetricProcessors) Apply(req *colmetrics.ExportMetricsServiceRequest) {
	if p == nil || len(p.stages) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.stages {
		if len(p.state[i]) > maxSeries {
			p.state[i] = map[string]*seriesState{}
		}
		if s.Type == "group_by_attrs" {
			req.ResourceMetrics = groupByAttrs(req.GetResourceMetrics(), s.Keys)
			continue
		}
		for _, rm := range req.GetResourceMetrics() {
			rk := attrKey(rm.GetResource().GetAttributes())
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					p.metric(i, s.Type, rk+"\x01"+sm.GetScope().GetName()+"\x01"+m.GetName(), m)
				}
			}
		}
	}
}

func (p *MetricProcessors) get(i int, key string, start uint64) (*seriesState, bool) {
	st, ok := p.state[i][key]
	if !ok {
		st = &seriesState{start: start}
		p.state[i][key] = st
	}
	return st, ok
}

func (p *MetricProcessors) metric(i int, typ, key string, m *metricspb.Metric) {
	cumul := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	delta := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
	switch d := m.GetData().(type) {
	case *metricspb.Metric_Sum:
		s := d.Sum
		switch {
		case typ == "cumulative_to_delta" && s.GetAggregationTemporality() == cumul && s.GetIsMonotonic():
			s.DataPoints = slices.DeleteFunc(s.DataPoints, func(dp *metricspb.NumberDataPoint) bool {
				st, seen := p.get(i, key+attrKey(dp.GetAttributes()), dp.GetStartTimeUnixNano())
				v, prev, prevT := num(dp), st.sum, st.t
				st.sum, st.t = v, dp.GetTimeUnixNano()
				if !seen {
					return true
				}
				if v < prev { // counter reset
					prev = 0
				}
				setNum(dp, v-prev)
				dp.StartTimeUnixNano = prevT
				return false
			})
			s.AggregationTemporality = delta
		case typ == "delta_to_cumulative" && s.GetAggregationTemporality() == delta:
			for _, dp := range s.DataPoints {
				st, _ := p.get(i, key+attrKey(dp.GetAttributes()), dp.GetStartTimeUnixNano())
				st.sum += num(dp)
				setNum(dp, st.sum)
				dp.StartTimeUnixNano = st.start
			}
			s.AggregationTemporality = cumul
		case typ == "metric_start_time" && s.GetAggregationTemporality() == cumul:
			for _, dp := range s.DataPoints {
				st, _ := p.get(i, key+attrKey(dp.GetAttributes()), dp.GetTimeUnixNano())
				if dp.StartTimeUnixNano == 0 {
					dp.StartTimeUnixNano = st.start
				}
			}
		case typ == "interval" && s.GetAggregationTemporality() == cumul:
			s.DataPoints = p.thin(i, key, s.DataPoints)
		}
	case *metricspb.Metric_Gauge:
		if typ == "interval" {
			d.Gauge.DataPoints = p.thin(i, key, d.Gauge.DataPoints)
		}
	case *metricspb.Metric_Histogram:
		p.histogram(i, typ, key, d.Histogram)
	}
}

// thin keeps the first point per series per interval. shortcut: otelcol's interval emits the
// last point at the window's end; this keeps the first (no timer, no buffering).
func (p *MetricProcessors) thin(i int, key string, dps []*metricspb.NumberDataPoint) []*metricspb.NumberDataPoint {
	now := p.now()
	return slices.DeleteFunc(dps, func(dp *metricspb.NumberDataPoint) bool {
		st, seen := p.get(i, key+attrKey(dp.GetAttributes()), 0)
		if seen && now.Sub(st.emitted) < p.every[i] {
			return true
		}
		st.emitted = now
		return false
	})
}

func (p *MetricProcessors) histogram(i int, typ, key string, h *metricspb.Histogram) {
	cumul := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	delta := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
	switch {
	case typ == "cumulative_to_delta" && h.GetAggregationTemporality() == cumul:
		h.DataPoints = slices.DeleteFunc(h.DataPoints, func(dp *metricspb.HistogramDataPoint) bool {
			st, seen := p.get(i, key+attrKey(dp.GetAttributes()), dp.GetStartTimeUnixNano())
			prev, prevT, prevSum, prevB := st.count, st.t, st.hsum, st.buckets
			st.count, st.t, st.hsum, st.buckets = dp.GetCount(), dp.GetTimeUnixNano(), dp.GetSum(), slices.Clone(dp.GetBucketCounts())
			if !seen || dp.GetCount() < prev || len(prevB) != len(dp.BucketCounts) {
				return !seen // a reset or a bucket layout change starts over with this point
			}
			dp.Count -= prev
			if dp.Sum != nil {
				v := dp.GetSum() - prevSum
				dp.Sum = &v
			}
			for j := range dp.BucketCounts {
				dp.BucketCounts[j] -= prevB[j]
			}
			dp.StartTimeUnixNano = prevT
			return false
		})
		h.AggregationTemporality = delta
	case typ == "delta_to_cumulative" && h.GetAggregationTemporality() == delta:
		for _, dp := range h.DataPoints {
			st, _ := p.get(i, key+attrKey(dp.GetAttributes()), dp.GetStartTimeUnixNano())
			if len(st.buckets) != len(dp.BucketCounts) {
				st.buckets, st.count, st.hsum = make([]uint64, len(dp.BucketCounts)), 0, 0
			}
			st.count += dp.GetCount()
			st.hsum += dp.GetSum()
			for j, c := range dp.BucketCounts {
				st.buckets[j] += c
			}
			dp.Count, dp.BucketCounts, dp.StartTimeUnixNano = st.count, slices.Clone(st.buckets), st.start
			if dp.Sum != nil {
				v := st.hsum
				dp.Sum = &v
			}
		}
		h.AggregationTemporality = cumul
	case typ == "metric_start_time" && h.GetAggregationTemporality() == cumul:
		for _, dp := range h.DataPoints {
			st, _ := p.get(i, key+attrKey(dp.GetAttributes()), dp.GetTimeUnixNano())
			if dp.StartTimeUnixNano == 0 {
				dp.StartTimeUnixNano = st.start
			}
		}
	}
}

func num(dp *metricspb.NumberDataPoint) float64 {
	if v, ok := dp.GetValue().(*metricspb.NumberDataPoint_AsInt); ok {
		return float64(v.AsInt)
	}
	return dp.GetAsDouble()
}

func setNum(dp *metricspb.NumberDataPoint, v float64) {
	if _, ok := dp.GetValue().(*metricspb.NumberDataPoint_AsInt); ok {
		dp.Value = &metricspb.NumberDataPoint_AsInt{AsInt: int64(v)}
		return
	}
	dp.Value = &metricspb.NumberDataPoint_AsDouble{AsDouble: v}
}

// groupByAttrs moves keys from Sum and Gauge points to the resource, one ResourceMetrics per
// distinct value set.
func groupByAttrs(rms []*metricspb.ResourceMetrics, keys []string) []*metricspb.ResourceMetrics {
	var out []*metricspb.ResourceMetrics
	for _, rm := range rms {
		groups := map[string]*metricspb.ResourceMetrics{}
		var order []string
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				var dps []*metricspb.NumberDataPoint
				switch d := m.GetData().(type) {
				case *metricspb.Metric_Sum:
					dps = d.Sum.GetDataPoints()
				case *metricspb.Metric_Gauge:
					dps = d.Gauge.GetDataPoints()
				default:
					dps = nil
				}
				if dps == nil {
					g := group(groups, &order, rm, "", nil)
					appendMetric(g, sm, m)
					continue
				}
				for _, dp := range dps {
					var moved []*commonpb.KeyValue
					dp.Attributes = slices.DeleteFunc(dp.Attributes, func(kv *commonpb.KeyValue) bool {
						if slices.Contains(keys, kv.GetKey()) {
							moved = append(moved, kv)
							return true
						}
						return false
					})
					g := group(groups, &order, rm, attrKey(moved), moved)
					cp := &metricspb.Metric{Name: m.GetName(), Description: m.GetDescription(), Unit: m.GetUnit()}
					switch d := m.GetData().(type) {
					case *metricspb.Metric_Sum:
						cp.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{AggregationTemporality: d.Sum.GetAggregationTemporality(),
							IsMonotonic: d.Sum.GetIsMonotonic(), DataPoints: []*metricspb.NumberDataPoint{dp}}}
					case *metricspb.Metric_Gauge:
						cp.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{dp}}}
					}
					appendMetric(g, sm, cp)
				}
			}
		}
		for _, k := range order {
			out = append(out, groups[k])
		}
	}
	return out
}

func group(groups map[string]*metricspb.ResourceMetrics, order *[]string, rm *metricspb.ResourceMetrics, k string, moved []*commonpb.KeyValue) *metricspb.ResourceMetrics {
	if g, ok := groups[k]; ok {
		return g
	}
	attrs := slices.Clone(rm.GetResource().GetAttributes())
	attrs = append(attrs, moved...)
	g := &metricspb.ResourceMetrics{Resource: &resourcepb.Resource{Attributes: attrs}, SchemaUrl: rm.GetSchemaUrl()}
	groups[k] = g
	*order = append(*order, k)
	return g
}

func appendMetric(g *metricspb.ResourceMetrics, sm *metricspb.ScopeMetrics, m *metricspb.Metric) {
	for _, s := range g.ScopeMetrics {
		if s.GetScope().GetName() == sm.GetScope().GetName() {
			s.Metrics = append(s.Metrics, m)
			return
		}
	}
	g.ScopeMetrics = append(g.ScopeMetrics, &metricspb.ScopeMetrics{Scope: sm.GetScope(), SchemaUrl: sm.GetSchemaUrl(), Metrics: []*metricspb.Metric{m}})
}
