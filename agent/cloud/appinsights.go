package cloud

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// Azure Application Insights traces (TRC-007). A workspace-based App Insights resource streams its
// AppRequests and AppDependencies tables to Event Hubs through a diagnostic setting; the
// azure_eventhub module reads them and this file turns each row into an OTLP span (requests are
// SERVER spans, dependencies CLIENT, PRODUCER or INTERNAL). W3C ids are kept as they are, so the
// spans join traces from OTel-instrumented services; legacy hierarchical ids are hashed.

type aiRecord struct {
	Time            string            `json:"time"`
	TimeGenerated   string            `json:"TimeGenerated"`
	Type            string            `json:"Type"`
	Category        string            `json:"category"`
	ResourceID      string            `json:"resourceId"`
	ID              string            `json:"Id"`
	OperationID     string            `json:"OperationId"`
	ParentID        string            `json:"ParentId"`
	Name            string            `json:"Name"`
	URL             string            `json:"Url"`
	Target          string            `json:"Target"`
	DependencyType  string            `json:"DependencyType"`
	Data            string            `json:"Data"`
	Success         *bool             `json:"Success"`
	ResultCode      string            `json:"ResultCode"`
	DurationMs      float64           `json:"DurationMs"`
	AppRoleName     string            `json:"AppRoleName"`
	AppRoleInstance string            `json:"AppRoleInstance"`
	ClientIP        string            `json:"ClientIP"`
	Properties      map[string]string `json:"Properties"`
}

const aiMaxProps = 64

// aiID returns the hex id when s already is one of n bytes, else the first n bytes of its SHA-256.
func aiID(s string, n int) []byte {
	if b, err := hex.DecodeString(s); err == nil && len(b) == n {
		return b
	}
	h := sha256.Sum256([]byte(s))
	return h[:n]
}

func aiKind(table, depType string) tracepb.Span_SpanKind {
	if table == "AppRequests" {
		return tracepb.Span_SPAN_KIND_SERVER
	}
	t := strings.ToLower(depType)
	switch {
	case t == "inproc":
		return tracepb.Span_SPAN_KIND_INTERNAL
	case strings.Contains(t, "queue") || strings.Contains(t, "service bus") || strings.Contains(t, "event hub"):
		return tracepb.Span_SPAN_KIND_PRODUCER
	}
	return tracepb.Span_SPAN_KIND_CLIENT
}

// appInsightsSpan converts one Event Hubs record; ok is false for anything but an AppRequests or
// AppDependencies row with an id and an operation id.
func appInsightsSpan(raw json.RawMessage) (res map[string]string, sp *tracepb.Span, ok bool) {
	var r aiRecord
	if json.Unmarshal(raw, &r) != nil {
		return nil, nil, false
	}
	table := r.Type
	if table == "" {
		table = r.Category
	}
	if (table != "AppRequests" && table != "AppDependencies") || r.ID == "" || r.OperationID == "" {
		return nil, nil, false
	}
	start, err := time.Parse(time.RFC3339Nano, r.Time)
	if err != nil {
		if start, err = time.Parse(time.RFC3339Nano, r.TimeGenerated); err != nil {
			return nil, nil, false
		}
	}
	end := start.Add(time.Duration(max(r.DurationMs, 0) * float64(time.Millisecond)))
	sp = &tracepb.Span{TraceId: aiID(r.OperationID, 16), SpanId: aiID(r.ID, 8), Name: r.Name,
		Kind: aiKind(table, r.DependencyType), Status: &tracepb.Status{}}
	sp.StartTimeUnixNano, sp.EndTimeUnixNano = uint64(start.UnixNano()), uint64(end.UnixNano()) //nolint:gosec // post-1970 timestamps
	if r.ParentID != "" && r.ParentID != r.OperationID {
		sp.ParentSpanId = aiID(r.ParentID, 8)
	}
	if r.Success != nil && !*r.Success {
		sp.Status.Code = tracepb.Status_STATUS_CODE_ERROR
	}
	add := func(k, v string) {
		if v != "" && !strings.HasPrefix(k, "wt.") {
			sp.Attributes = append(sp.Attributes, sfnKV(k, v))
		}
	}
	if code, err := strconv.Atoi(r.ResultCode); err == nil && (table == "AppRequests" || strings.EqualFold(r.DependencyType, "HTTP")) {
		sp.Attributes = append(sp.Attributes, &commonpb.KeyValue{Key: "http.response.status_code",
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(code)}}})
	} else {
		add("azure.appinsights.result_code", r.ResultCode)
	}
	add("url.full", r.URL)
	add("client.address", r.ClientIP)
	add("server.address", r.Target)
	add("azure.appinsights.dependency_type", r.DependencyType)
	if strings.Contains(strings.ToLower(r.DependencyType), "sql") {
		add("db.system", "mssql")
		add("db.query.text", r.Data)
	} else if strings.EqualFold(r.DependencyType, "HTTP") && r.URL == "" {
		add("url.full", r.Data)
	}
	keys := make([]string, 0, len(r.Properties))
	for k := range r.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys[:min(len(keys), aiMaxProps)] {
		add(k, r.Properties[k]) // custom dimensions keep their names
	}
	res = map[string]string{"cloud.provider": "azure", "telemetry.sdk.name": "applicationinsights"}
	if r.AppRoleName != "" {
		res["service.name"] = r.AppRoleName
	}
	if r.AppRoleInstance != "" {
		res["service.instance.id"] = r.AppRoleInstance
	}
	if r.ResourceID != "" {
		res["cloud.resource_id"] = strings.ToLower(r.ResourceID)
	}
	return res, sp, true
}
