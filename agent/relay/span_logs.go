package relay

// span_to_log (CFT-A13, otelcol spanlogs connector parity): the relay writes one log record per
// span it forwards (all spans, root spans only, or spans with error status), carrying the
// trace/span ids, name, duration and status, so tools that only read logs see request lines.

import (
	"fmt"
	"strconv"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// SpanLogs configures span_to_log; Mode is all, root or error (empty: off).
type SpanLogs struct {
	Mode string `yaml:"mode"`
}

func (c SpanLogs) want(sp *tracepb.Span) bool {
	switch c.Mode {
	case "all":
		return true
	case "root":
		return len(sp.GetParentSpanId()) == 0
	case "error":
		return sp.GetStatus().GetCode() == tracepb.Status_STATUS_CODE_ERROR
	}
	return false
}

func kv(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: strVal(v)}
}

// SpanLogsFor builds the log records of a trace batch (nil when none).
func SpanLogsFor(c SpanLogs, req *coltrace.ExportTraceServiceRequest) *collogs.ExportLogsServiceRequest {
	out := &collogs.ExportLogsServiceRequest{}
	for _, rs := range req.GetResourceSpans() {
		rl := &logspb.ResourceLogs{Resource: rs.GetResource()}
		for _, ss := range rs.GetScopeSpans() {
			sl := &logspb.ScopeLogs{Scope: &commonpb.InstrumentationScope{Name: "wt.span_to_log"}}
			for _, sp := range ss.GetSpans() {
				if !c.want(sp) {
					continue
				}
				dur := float64(sp.GetEndTimeUnixNano()-sp.GetStartTimeUnixNano()) / 1e6
				sev, sevText := logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "INFO"
				if sp.GetStatus().GetCode() == tracepb.Status_STATUS_CODE_ERROR {
					sev, sevText = logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, "ERROR"
				}
				attrs := []*commonpb.KeyValue{kv("span.name", sp.GetName()), kv("span.kind", sp.GetKind().String()),
					kv("span.duration_ms", strconv.FormatFloat(dur, 'f', 3, 64)), kv("span.status", sp.GetStatus().GetCode().String())}
				for _, a := range sp.GetAttributes() {
					if len(attrs) < maxAttrs {
						attrs = append(attrs, a)
					}
				}
				sl.LogRecords = append(sl.LogRecords, &logspb.LogRecord{
					TimeUnixNano: sp.GetEndTimeUnixNano(), ObservedTimeUnixNano: sp.GetEndTimeUnixNano(),
					SeverityNumber: sev, SeverityText: sevText, TraceId: sp.GetTraceId(), SpanId: sp.GetSpanId(),
					Body:       strVal(fmt.Sprintf("%s %s %.3fms", sp.GetName(), sp.GetStatus().GetCode().String(), dur)),
					Attributes: attrs,
				})
			}
			if len(sl.LogRecords) > 0 {
				rl.ScopeLogs = append(rl.ScopeLogs, sl)
			}
		}
		if len(rl.ScopeLogs) > 0 {
			out.ResourceLogs = append(out.ResourceLogs, rl)
		}
	}
	if len(out.ResourceLogs) == 0 {
		return nil
	}
	return out
}
