package srcconv

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	colllogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// HECEvt is one Splunk HTTP Event Collector event.
type HECEvt struct {
	Time       any            `json:"time"`
	Host       string         `json:"host"`
	Source     string         `json:"source"`
	Sourcetype string         `json:"sourcetype"`
	Index      string         `json:"index"`
	Service    string         `json:"service"`
	Event      any            `json:"event"`
	Fields     map[string]any `json:"fields"`
}

// Meta appends the event's host, source, sourcetype and index as attributes.
func (e *HECEvt) Meta(attrs []*commonpb.KeyValue) []*commonpb.KeyValue {
	for _, p := range [][2]string{
		{"host.name", e.Host}, {"log.file.path", e.Source}, {"splunk.sourcetype", e.Sourcetype}, {"splunk.index", e.Index},
	} {
		if p[1] != "" {
			attrs = AppendKV(attrs, p[0], StrVal(p[1]))
		}
	}
	return attrs
}

// ErrHECFormat is a body that is not a stream of HEC events.
var ErrHECFormat = errors.New("invalid data format")

// HECDecode reads a stream of concatenated JSON events (numbers exact). More than max events is
// ErrTooLarge.
func HECDecode(body []byte, max int) ([]HECEvt, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var out []HECEvt
	for {
		var e HECEvt
		if err := dec.Decode(&e); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil || e.Event == nil {
			return nil, ErrHECFormat
		}
		if len(out) >= max {
			return nil, ErrTooLarge
		}
		out = append(out, e)
	}
}

// HECRequests converts events: log events to one logs request, `event:"metric"` events to gauges
// in one metrics request (nil when there are none). now is unix ns.
func HECRequests(evs []HECEvt, now uint64) (*colllogs.ExportLogsServiceRequest, *collmetrics.ExportMetricsServiceRequest) {
	lreq := &colllogs.ExportLogsServiceRequest{}
	var sl *logspb.ScopeLogs                // created on the first event without a service
	bySvc := map[string]*logspb.ScopeLogs{} // one resource per service.name
	var gauges []*metricspb.Metric
	for i := range evs {
		e := &evs[i]
		ns := ParseTime(e.Time, 1e9)
		if s, isStr := e.Event.(string); isStr && s == "metric" && e.Fields != nil {
			gauges = append(gauges, HECGauges(e, ns, now)...)
			continue
		}
		var dst *logspb.ScopeLogs
		if svc := e.ServiceName(); svc != "" {
			if bySvc[svc] == nil {
				bySvc[svc] = NewScope(lreq, []*commonpb.KeyValue{{Key: "service.name", Value: StrVal(svc)}})
			}
			dst = bySvc[svc]
		} else {
			if sl == nil {
				sl = NewScope(lreq, nil)
			}
			dst = sl
		}
		dst.LogRecords = append(dst.LogRecords, HECLog(e, ns, now))
	}
	var mreq *collmetrics.ExportMetricsServiceRequest
	if len(gauges) > 0 {
		mreq = &collmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource:     &resourcepb.Resource{},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: gauges}},
		}}}
	}
	return lreq, mreq
}

// ServiceName is the event's service: the top-level `service`, else fields.service, else
// service in a JSON event object.
func (e *HECEvt) ServiceName() string {
	if e.Service != "" {
		return e.Service
	}
	if s, ok := e.Fields["service"].(string); ok && s != "" {
		return s
	}
	if m, ok := e.Event.(map[string]any); ok {
		s, _ := m["service"].(string)
		return s
	}
	return ""
}

// HECLog converts one log event.
func HECLog(e *HECEvt, ns, now uint64) *logspb.LogRecord {
	attrs := e.Meta(nil)
	for _, k := range SortedKeys(e.Fields) {
		attrs = AppendKV(attrs, k, JSONVal(e.Fields[k]))
	}
	if s, ok := e.Event.(string); ok {
		return LogRecord(ns, now, s, attrs)
	}
	flat := map[string]any{}
	Flatten("", e.Event, flat)
	for _, k := range SortedKeys(flat) {
		attrs = AppendKV(attrs, k, JSONVal(flat[k]))
	}
	b, _ := json.Marshal(DropWt(e.Event))
	return LogRecord(ns, now, string(b), attrs)
}

// DropWt removes reserved wt.* keys from a decoded JSON value so they cannot reach storage in the body either.
func DropWt(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if !strings.HasPrefix(k, "wt.") {
				out[k] = DropWt(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = DropWt(x)
		}
		return out
	}
	return v
}

// HECGauges maps a metric event: fields {metric_name, _value} or {"metric_name:<name>": value, ...};
// every other field is a dimension.
func HECGauges(e *HECEvt, ns, now uint64) []*metricspb.Metric {
	if ns == 0 {
		ns = now
	}
	var dims []*commonpb.KeyValue
	dims = e.Meta(dims)
	vals := map[string]float64{}
	for _, k := range SortedKeys(e.Fields) {
		v := e.Fields[k]
		if num, ok := v.(json.Number); ok {
			if f, err := num.Float64(); err == nil {
				if name, ok := strings.CutPrefix(k, "metric_name:"); ok {
					vals[name] = f
					continue
				}
				if k == "_value" {
					if name, _ := e.Fields["metric_name"].(string); name != "" {
						vals[name] = f
					}
					continue
				}
			}
		}
		if k != "metric_name" {
			dims = AppendKV(dims, k, JSONVal(v))
		}
	}
	var out []*metricspb.Metric
	for _, name := range SortedKeys(vals) {
		out = append(out, &metricspb.Metric{Name: name, Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{
			DataPoints: []*metricspb.NumberDataPoint{{
				TimeUnixNano: ns, Attributes: dims,
				Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: vals[name]},
			}},
		}}})
	}
	return out
}

// HECRawRequest turns a raw body (one event per non-empty line) into logs; max lines at most.
func HECRawRequest(body string, e HECEvt, now uint64, max int) (*colllogs.ExportLogsServiceRequest, error) {
	req := &colllogs.ExportLogsServiceRequest{}
	var attrs []*commonpb.KeyValue
	if e.Service != "" {
		attrs = []*commonpb.KeyValue{{Key: "service.name", Value: StrVal(e.Service)}}
	}
	sl := NewScope(req, attrs)
	for _, line := range strings.Split(body, "\n") {
		if line = strings.TrimRight(line, "\r"); line == "" {
			continue
		}
		if len(sl.LogRecords) >= max {
			return nil, ErrTooLarge
		}
		sl.LogRecords = append(sl.LogRecords, LogRecord(0, now, line, e.Meta(nil)))
	}
	if len(sl.LogRecords) == 0 {
		return nil, ErrHECFormat
	}
	return req, nil
}

// HECLogCount is the number of log records in a HECRequests logs request.
func HECLogCount(req *colllogs.ExportLogsServiceRequest) (n int) {
	for _, rl := range req.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			n += len(sl.LogRecords)
		}
	}
	return n
}
