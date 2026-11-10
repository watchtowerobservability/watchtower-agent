package relay

import (
	"fmt"
	"strconv"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// Event is one log record, span or metric point flattened for the destinations (destinations.go).
// It is what the dedupe and quota processors see and what every destination encodes.
type Event struct {
	Kind       string            `json:"kind"` // log, span or metric
	Time       time.Time         `json:"timestamp"`
	Name       string            `json:"name,omitempty"` // metric name or span name
	Message    string            `json:"message,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Service    string            `json:"service,omitempty"`
	TraceID    string            `json:"trace_id,omitempty"`
	SpanID     string            `json:"span_id,omitempty"`
	ParentID   string            `json:"parent_span_id,omitempty"`
	DurationNs int64             `json:"duration_ns,omitempty"` // spans
	Error      bool              `json:"error,omitempty"`       // spans; Message then holds the status message
	Value      *float64          `json:"value,omitempty"`
	MetricType string            `json:"metric_type,omitempty"` // gauge or count
	Attrs      map[string]string `json:"attributes,omitempty"`  // record attributes over resource attributes
}

func anyStr(v *commonpb.AnyValue) string {
	switch x := v.GetValue().(type) {
	case nil:
		return ""
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	}
	return fmt.Sprint(v) // arrays, maps, bytes: the protobuf text form is enough for a forwarded copy
}

func attrMap(dst map[string]string, kv []*commonpb.KeyValue) {
	for _, a := range kv {
		dst[a.Key] = anyStr(a.Value)
	}
}

func nanos(n uint64) time.Time {
	if n == 0 {
		return time.Now().UTC()
	}
	return time.Unix(0, int64(n)).UTC()
}

func resAttrs(kv []*commonpb.KeyValue) (map[string]string, string) {
	m := map[string]string{}
	attrMap(m, kv)
	return m, m["service.name"]
}

func merged(res map[string]string, kv []*commonpb.KeyValue) map[string]string {
	m := make(map[string]string, len(res)+len(kv))
	for k, v := range res {
		m[k] = v
	}
	attrMap(m, kv)
	return m
}

// EventsOf flattens a processed OTLP request (logs, traces or metrics); other messages give none.
// Histogram and summary points become `<name>.count` and `<name>.sum` count events.
func EventsOf(m proto.Message) []Event {
	var out []Event
	switch r := m.(type) {
	case *collogs.ExportLogsServiceRequest:
		for _, rl := range r.ResourceLogs {
			res, svc := resAttrs(rl.GetResource().GetAttributes())
			for _, sl := range rl.ScopeLogs {
				for _, l := range sl.LogRecords {
					t := l.TimeUnixNano
					if t == 0 {
						t = l.ObservedTimeUnixNano
					}
					out = append(out, Event{Kind: "log", Time: nanos(t), Message: anyStr(l.Body), Severity: l.SeverityText,
						Service: svc, TraceID: hexOf(l.TraceId), SpanID: hexOf(l.SpanId), Attrs: merged(res, l.Attributes)})
				}
			}
		}
	case *coltrace.ExportTraceServiceRequest:
		for _, rs := range r.ResourceSpans {
			res, svc := resAttrs(rs.GetResource().GetAttributes())
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					out = append(out, Event{Kind: "span", Time: nanos(s.StartTimeUnixNano), Name: s.Name, Service: svc,
						TraceID: hexOf(s.TraceId), SpanID: hexOf(s.SpanId), ParentID: hexOf(s.ParentSpanId),
						DurationNs: int64(s.EndTimeUnixNano) - int64(s.StartTimeUnixNano), Error: s.GetStatus().GetCode() == tracepb.Status_STATUS_CODE_ERROR,
						Message: s.GetStatus().GetMessage(), Attrs: merged(res, s.Attributes)})
				}
			}
		}
	case *colmetrics.ExportMetricsServiceRequest:
		for _, rm := range r.ResourceMetrics {
			res, svc := resAttrs(rm.GetResource().GetAttributes())
			for _, sm := range rm.ScopeMetrics {
				for _, mt := range sm.Metrics {
					out = append(out, metricEvents(mt.Name, mt, svc, res)...)
				}
			}
		}
	}
	return out
}

func hexOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", b)
}
