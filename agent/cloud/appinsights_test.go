package cloud

import (
	"encoding/hex"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func aiAttr(sp *tracepb.Span, k string) string {
	for _, kv := range sp.Attributes {
		if kv.Key == k {
			return kv.Value.GetStringValue()
		}
	}
	return ""
}

func TestAppInsightsRowsBecomeSpans(t *testing.T) {
	msg := `{"records":[
	 {"time":"2026-10-28T10:00:00Z","Type":"AppRequests","Id":"b7ad6b7169203331","OperationId":"0af7651916cd43dd8448eb211c80319c",
	  "ParentId":"0af7651916cd43dd8448eb211c80319c","Name":"POST /pay","Url":"https://shop.example/pay","Success":false,
	  "ResultCode":"500","DurationMs":250,"AppRoleName":"checkout","AppRoleInstance":"vm-1","Properties":{"tier":"gold","wt.project_id":"evil"}},
	 {"time":"2026-10-28T10:00:00.05Z","Type":"AppDependencies","Id":"|abc.1.","OperationId":"0af7651916cd43dd8448eb211c80319c",
	  "ParentId":"b7ad6b7169203331","Name":"SQL: orders","Target":"db.example","DependencyType":"SQL","Data":"SELECT 1",
	  "Success":true,"ResultCode":"0","DurationMs":12,"AppRoleName":"checkout"},
	 {"time":"2026-10-28T10:00:00Z","category":"AuditEvent","operationName":"Get","level":"Warning"}]}`
	rec := &sink.Recorder{}
	var got []*tracepb.Span
	var res []map[string]string
	ProcessWith(rec, func(r map[string]string, s []*tracepb.Span) { res = append(res, r); got = append(got, s...) }, []byte(msg), time.Now())
	if len(got) != 2 || len(rec.Samples) != 1 {
		t.Fatalf("want 2 spans and 1 log, got %d spans, %d samples", len(got), len(rec.Samples))
	}
	req, dep := got[0], got[1]
	if hex.EncodeToString(req.TraceId) != "0af7651916cd43dd8448eb211c80319c" || req.Kind != tracepb.Span_SPAN_KIND_SERVER ||
		len(req.ParentSpanId) != 0 || req.Status.Code != tracepb.Status_STATUS_CODE_ERROR ||
		req.EndTimeUnixNano-req.StartTimeUnixNano != uint64(250*time.Millisecond) {
		t.Fatalf("request span: %+v", req)
	}
	if res[0]["service.name"] != "checkout" || res[0]["service.instance.id"] != "vm-1" {
		t.Fatalf("resource: %v", res[0])
	}
	if aiAttr(req, "tier") != "gold" || aiAttr(req, "wt.project_id") != "" {
		t.Fatalf("properties: %v", req.Attributes)
	}
	if dep.Kind != tracepb.Span_SPAN_KIND_CLIENT || hex.EncodeToString(dep.ParentSpanId) != "b7ad6b7169203331" ||
		len(dep.SpanId) != 8 || aiAttr(dep, "db.query.text") != "SELECT 1" || aiAttr(dep, "server.address") != "db.example" {
		t.Fatalf("dependency span: %+v", dep)
	}
	// without a span shipper the rows stay logs (the old behaviour)
	rec = &sink.Recorder{}
	Process(rec, []byte(msg), time.Now())
	if len(rec.Samples) != 3 {
		t.Fatalf("Process must keep logging every record, got %d", len(rec.Samples))
	}
}
