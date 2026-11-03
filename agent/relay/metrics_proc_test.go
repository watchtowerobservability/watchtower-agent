package relay

import (
	"testing"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func sumReq(temp metricspb.AggregationTemporality, v float64, t uint64) *colmetrics.ExportMetricsServiceRequest {
	dp := &metricspb.NumberDataPoint{TimeUnixNano: t, Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: v},
		Attributes: []*commonpb.KeyValue{{Key: "pod", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "a"}}}}}
	return &colmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{
		Metrics: []*metricspb.Metric{{Name: "req", Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			AggregationTemporality: temp, IsMonotonic: true, DataPoints: []*metricspb.NumberDataPoint{dp}}}}}}}}}}
}

func pts(r *colmetrics.ExportMetricsServiceRequest) []*metricspb.NumberDataPoint {
	return r.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetSum().GetDataPoints()
}

func TestCumulativeToDeltaAndBack(t *testing.T) {
	cum := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	p, err := CompileMetrics([]MetricStage{{Type: "cumulative_to_delta"}})
	if err != nil {
		t.Fatal(err)
	}
	r1 := sumReq(cum, 10, 1)
	p.Apply(r1)
	if len(pts(r1)) != 0 {
		t.Fatal("first point must only prime the state")
	}
	r2 := sumReq(cum, 15, 2)
	p.Apply(r2)
	if got := pts(r2)[0].GetAsDouble(); got != 5 || pts(r2)[0].StartTimeUnixNano != 1 {
		t.Fatalf("delta %v start %d", got, pts(r2)[0].StartTimeUnixNano)
	}
	r3 := sumReq(cum, 3, 3) // reset
	p.Apply(r3)
	if got := pts(r3)[0].GetAsDouble(); got != 3 {
		t.Fatalf("after reset %v", got)
	}
	back, _ := CompileMetrics([]MetricStage{{Type: "delta_to_cumulative"}})
	back.Apply(r2)
	back.Apply(r3)
	if got := pts(r3)[0].GetAsDouble(); got != 8 {
		t.Fatalf("cumulative %v", got)
	}
}

func TestGroupByAttrsMovesKeyToResource(t *testing.T) {
	p, _ := CompileMetrics([]MetricStage{{Type: "group_by_attrs", Keys: []string{"pod"}}})
	r := sumReq(metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, 1, 1)
	p.Apply(r)
	if a := r.ResourceMetrics[0].Resource.Attributes; len(a) != 1 || a[0].Key != "pod" || len(pts(r)[0].Attributes) != 0 {
		t.Fatalf("%v", r)
	}
	if _, err := CompileMetrics([]MetricStage{{Type: "bogus"}}); err == nil {
		t.Fatal("unknown stage accepted")
	}
}

func TestSpanLogsRootOnly(t *testing.T) {
	req := &coltrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{
		{Name: "GET /", TraceId: make([]byte, 16), SpanId: []byte{1, 2, 3, 4, 5, 6, 7, 8}, StartTimeUnixNano: 1e6, EndTimeUnixNano: 3e6},
		{Name: "db", ParentSpanId: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}}}}}}
	l := SpanLogsFor(SpanLogs{Mode: "root"}, req)
	recs := l.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()
	if len(recs) != 1 || recs[0].GetBody().GetStringValue() != "GET / STATUS_CODE_UNSET 2.000ms" {
		t.Fatalf("%v", recs)
	}
	if SpanLogsFor(SpanLogs{}, req) != nil {
		t.Fatal("off must emit nothing")
	}
}
