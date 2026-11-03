package main

import (
	"testing"
	"time"
)

func TestHistogramPointsBecomeOneCumulativeHistogram(t *testing.T) {
	o := NewOTLP("http://x", "t", nil)
	at := time.Unix(10, 0)
	o.Histogram("h", "s", []float64{1, 2}, []uint64{1, 0, 2}, 7, 3, map[string]string{"a": "1"}, at)
	o.Histogram("h", "s", []float64{1, 2}, []uint64{0, 1, 0}, 1.5, 1, map[string]string{"a": "2"}, at)
	o.Sum("h", "s", 1, map[string]string{"a": "1"}, at) // same name, other kind: a separate metric
	ms := o.MetricsRequest(o.points).ResourceMetrics[0].ScopeMetrics[0].Metrics
	if len(ms) != 2 {
		t.Fatal(len(ms))
	}
	h := ms[0].GetHistogram()
	if h == nil || h.AggregationTemporality != 2 || len(h.DataPoints) != 2 { // 2 = cumulative
		t.Fatal(ms[0])
	}
	dp := h.DataPoints[0]
	if dp.Count != 3 || dp.GetSum() != 7 || len(dp.BucketCounts) != 3 || len(dp.ExplicitBounds) != 2 {
		t.Fatal(dp)
	}
	if o.points[0].size <= o.points[2].size {
		t.Fatal("histogram size estimate does not count buckets")
	}
}
