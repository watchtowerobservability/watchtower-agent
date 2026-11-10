package srcconv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	colllogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	colltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

// ErrDatadog is a malformed Datadog payload; ErrTooLarge a payload past the field budget.
var (
	ErrDatadog  = errors.New("malformed datadog payload")
	ErrTooLarge = errors.New("payload too large")
)

// ---- logs ----

// DDLogsRequest converts Datadog v2 log entries (one resource per service) to OTLP.
func DDLogsRequest(entries []map[string]any, now uint64) *colllogs.ExportLogsServiceRequest {
	req := &colllogs.ExportLogsServiceRequest{}
	by := map[string]*logspb.ScopeLogs{}
	for _, e := range entries {
		svc, _ := e["service"].(string)
		sl := by[svc]
		if sl == nil {
			var res []*commonpb.KeyValue
			if svc != "" {
				res = append(res, &commonpb.KeyValue{Key: "service.name", Value: StrVal(svc)})
			}
			sl = NewScope(req, res)
			by[svc] = sl
		}
		sl.LogRecords = append(sl.LogRecords, DDLog(e, now))
	}
	return req
}

// DDLogEntries decodes a Datadog logs body (a JSON array, numbers kept exact).
func DDLogEntries(body []byte) ([]map[string]any, error) {
	var entries []map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&entries); err != nil {
		return nil, ErrDatadog
	}
	return entries, nil
}

// DDLog converts one Datadog log entry.
func DDLog(e map[string]any, now uint64) *logspb.LogRecord {
	msg, _ := e["message"].(string)
	var attrs []*commonpb.KeyValue
	if v, _ := e["hostname"].(string); v != "" {
		attrs = AppendKV(attrs, "host.name", StrVal(v))
	}
	if v, _ := e["ddsource"].(string); v != "" {
		attrs = AppendKV(attrs, "datadog.source", StrVal(v))
	}
	if tags, _ := e["ddtags"].(string); tags != "" {
		for _, t := range strings.Split(tags, ",") {
			if k, v, found := strings.Cut(t, ":"); found && k != "" {
				attrs = AppendKV(attrs, k, StrVal(v))
			}
		}
	}
	flat := map[string]any{}
	Flatten("", e, flat)
	for _, k := range SortedKeys(flat) {
		switch k {
		case "message", "hostname", "ddsource", "ddtags", "service", "status", "timestamp":
		default:
			attrs = AppendKV(attrs, k, JSONVal(flat[k]))
		}
	}
	rec := LogRecord(ParseTime(e["timestamp"], time.Millisecond), now, msg, attrs)
	if lvl, _ := e["status"].(string); lvl != "" {
		SetSeverity(rec, lvl)
	}
	return rec
}

// ---- traces ----

// MPU64 reads a msgpack/proto integer as uint64 (two's complement for large ids).
func MPU64(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int64:
		return uint64(x) //nolint:gosec // two's complement, as the agent sends large ids
	case float64:
		return uint64(x) //nolint:gosec // best effort
	}
	return 0
}

// MPStr reads a msgpack string or bin as a string.
func MPStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

func spanKind(s string) tracepb.Span_SpanKind {
	switch s {
	case "client":
		return tracepb.Span_SPAN_KIND_CLIENT
	case "server":
		return tracepb.Span_SPAN_KIND_SERVER
	case "producer":
		return tracepb.Span_SPAN_KIND_PRODUCER
	case "consumer":
		return tracepb.Span_SPAN_KIND_CONSUMER
	}
	return tracepb.Span_SPAN_KIND_INTERNAL
}

// DDSpan converts one span map. trace_id is 64-bit; the high half comes from meta `_dd.p.tid`.
func DDSpan(m map[string]any) (*tracepb.Span, string) {
	meta, _ := m["meta"].(map[string]any)
	tid := make([]byte, 16)
	if hi, err := hex.DecodeString(MPStr(meta["_dd.p.tid"])); err == nil && len(hi) == 8 {
		copy(tid, hi)
	}
	binary.BigEndian.PutUint64(tid[8:], MPU64(m["trace_id"]))
	sid := binary.BigEndian.AppendUint64(nil, MPU64(m["span_id"]))
	sp := &tracepb.Span{TraceId: tid, SpanId: sid, Name: MPStr(m["name"])}
	if p := MPU64(m["parent_id"]); p != 0 {
		sp.ParentSpanId = binary.BigEndian.AppendUint64(nil, p)
	}
	sp.StartTimeUnixNano = MPU64(m["start"])
	sp.EndTimeUnixNano = sp.StartTimeUnixNano + MPU64(m["duration"])
	if r := MPStr(m["resource"]); r != "" {
		sp.Attributes = AppendKV(sp.Attributes, "resource.name", StrVal(r))
	}
	if t := MPStr(m["type"]); t != "" {
		sp.Attributes = AppendKV(sp.Attributes, "dd.span.type", StrVal(t))
	}
	for _, k := range SortedKeys(meta) {
		switch k {
		case "_dd.p.tid":
		case "span.kind":
			sp.Kind = spanKind(MPStr(meta[k]))
		default:
			sp.Attributes = AppendKV(sp.Attributes, k, StrVal(MPStr(meta[k])))
		}
	}
	metrics, _ := m["metrics"].(map[string]any)
	for _, k := range SortedKeys(metrics) {
		if f, ok := metrics[k].(float64); ok {
			sp.Attributes = AppendKV(sp.Attributes, k, &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: f}})
		}
	}
	if MPU64(m["error"]) != 0 {
		sp.Status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: MPStr(meta["error.msg"])}
	}
	return sp, MPStr(m["service"])
}

// spanGroups batches spans into one ResourceSpans per service.name.
type spanGroups struct {
	by    map[string]*tracepb.ScopeSpans
	order []*tracepb.ResourceSpans
}

func newSpanGroups() *spanGroups { return &spanGroups{by: map[string]*tracepb.ScopeSpans{}} }

// add files sp under service (empty = "unknown_service"); extra are additional resource attributes.
func (g *spanGroups) add(service string, extra []*commonpb.KeyValue, sp *tracepb.Span) {
	if service == "" {
		service = "unknown_service"
	}
	ss := g.by[service]
	if ss == nil {
		ss = &tracepb.ScopeSpans{}
		g.by[service] = ss
		res := []*commonpb.KeyValue{{Key: "service.name", Value: StrVal(service)}}
		for _, kv := range extra {
			res = AppendKV(res, kv.Key, kv.Value)
		}
		g.order = append(g.order, &tracepb.ResourceSpans{
			Resource: &resourcepb.Resource{Attributes: res}, ScopeSpans: []*tracepb.ScopeSpans{ss},
		})
	}
	ss.Spans = append(ss.Spans, sp)
}

func (g *spanGroups) request() *colltrace.ExportTraceServiceRequest {
	return &colltrace.ExportTraceServiceRequest{ResourceSpans: g.order}
}

// DDTraces converts a decoded v0.4 payload (an array of traces, each an array of span maps) to OTLP,
// one resource per service. More than maxSpans spans is ErrTooLarge.
func DDTraces(v any, maxSpans int) (*colltrace.ExportTraceServiceRequest, error) {
	traces, ok := v.([]any)
	if !ok {
		return nil, ErrDatadog
	}
	g, n := newSpanGroups(), 0
	for _, t := range traces {
		spans, _ := t.([]any)
		for _, s := range spans {
			m, isMap := s.(map[string]any)
			if !isMap {
				return nil, ErrDatadog
			}
			if n++; n > maxSpans {
				return nil, ErrTooLarge
			}
			sp, svc := DDSpan(m)
			g.add(svc, nil, sp)
		}
	}
	return g.request(), nil
}

// ---- metrics ----

// Point is one series sample (TS in seconds).
type Point struct{ TS, Val float64 }

// UnmarshalJSON reads v1 [ts, value] pairs and v2 {"timestamp":..,"value":..} objects.
func (p *Point) UnmarshalJSON(b []byte) error {
	var arr []float64
	if json.Unmarshal(b, &arr) == nil && len(arr) == 2 {
		p.TS, p.Val = arr[0], arr[1]
		return nil
	}
	var o struct{ Timestamp, Value float64 }
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	p.TS, p.Val = o.Timestamp, o.Value
	return nil
}

// Series is a Datadog v1/v2 metric series.
type Series struct {
	Metric    string                        `json:"metric"`
	Type      json.RawMessage               `json:"type"` // v1 "gauge"|"count"|"rate"; v2 0..3
	Points    []Point                       `json:"points"`
	Tags      []string                      `json:"tags"`
	Host      string                        `json:"host"`
	Interval  float64                       `json:"interval"`
	Resources []struct{ Type, Name string } `json:"resources"`
}

// Kind maps both encodings to gauge, count or rate (v2: 1 count, 2 rate, 3 gauge; 0 = gauge).
func (s *Series) Kind() string {
	switch strings.Trim(string(s.Type), `"`) {
	case "count", "1":
		return "count"
	case "rate", "2":
		return "rate"
	}
	return "gauge"
}

// OTLP converts the series to a gauge or a delta sum.
func (s *Series) OTLP() *metricspb.Metric {
	attrs := []*commonpb.KeyValue{}
	host := s.Host
	for _, r := range s.Resources {
		if r.Type == "host" {
			host = r.Name
		}
	}
	if host != "" {
		attrs = AppendKV(attrs, "host.name", StrVal(host))
	}
	for _, t := range s.Tags {
		k, v, found := strings.Cut(t, ":")
		if !found {
			v = "true"
		}
		attrs = AppendKV(attrs, k, StrVal(v))
	}
	kind, interval := s.Kind(), s.Interval
	if interval <= 0 {
		interval = 10 // the agent's default flush interval
	}
	var pts []*metricspb.NumberDataPoint
	for _, p := range s.Points {
		v := p.Val
		if kind == "rate" {
			v *= interval // a rate over the interval is the delta it accumulated
		}
		dp := &metricspb.NumberDataPoint{
			TimeUnixNano: uint64(p.TS * 1e9), Attributes: attrs, //nolint:gosec // positive
			Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: v},
		}
		if kind != "gauge" {
			dp.StartTimeUnixNano = dp.TimeUnixNano - uint64(interval*1e9) //nolint:gosec // positive
		}
		pts = append(pts, dp)
	}
	m := &metricspb.Metric{Name: s.Metric}
	if kind == "gauge" {
		m.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: pts}}
	} else {
		// count and rate are increases: monotonic, so the worker types them as counters, unless
		// a point is a decrement (DogStatsD can send negative counts)
		mono := true
		for _, p := range pts {
			mono = mono && p.GetAsDouble() >= 0
		}
		m.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			DataPoints: pts, IsMonotonic: mono, AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		}}
	}
	return m
}

// Datadog-flavoured metric names to OTel semantic-convention names. The Agent's `system.*` gauges
// are also written under the OTel name; only gauges whose unit conversion is exact are listed.
type ddSem struct {
	name  string
	scale float64
	tag   string // extra `k:v` tag
}

var ddSemantic = map[string]ddSem{
	"system.cpu.user":   {"system.cpu.utilization", 0.01, "state:user"}, // percent -> ratio
	"system.cpu.system": {"system.cpu.utilization", 0.01, "state:system"},
	"system.cpu.idle":   {"system.cpu.utilization", 0.01, "state:idle"},
	"system.cpu.iowait": {"system.cpu.utilization", 0.01, "state:wait"},
	"system.load.1":     {"system.cpu.load_average.1m", 1, ""},
	"system.load.5":     {"system.cpu.load_average.5m", 1, ""},
	"system.load.15":    {"system.cpu.load_average.15m", 1, ""},
}

// SemanticTwin returns the OTel-named copy of a gauge series, or nil when there is none.
func (s *Series) SemanticTwin() *Series {
	m, ok := ddSemantic[s.Metric]
	if !ok || s.Kind() != "gauge" {
		return nil
	}
	t := *s
	t.Metric = m.name
	t.Points = make([]Point, len(s.Points))
	for i, p := range s.Points {
		t.Points[i] = Point{TS: p.TS, Val: p.Val * m.scale}
	}
	if m.tag != "" {
		t.Tags = append(append([]string(nil), s.Tags...), m.tag)
	}
	return &t
}

// SeriesRequest converts series (empty ones skipped, semantic twins added) to one OTLP request.
func SeriesRequest(series []Series) *collmetrics.ExportMetricsServiceRequest {
	sm := &metricspb.ScopeMetrics{}
	for i := range series {
		if series[i].Metric != "" && len(series[i].Points) > 0 {
			sm.Metrics = append(sm.Metrics, series[i].OTLP())
			if t := series[i].SemanticTwin(); t != nil {
				sm.Metrics = append(sm.Metrics, t.OTLP())
			}
		}
	}
	return &collmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{}, ScopeMetrics: []*metricspb.ScopeMetrics{sm},
	}}}
}

// SeriesFromJSON decodes a v1 or v2 JSON series body.
func SeriesFromJSON(body []byte) ([]Series, error) {
	var in struct {
		Series []Series `json:"series"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, err
	}
	return in.Series, nil
}

// SeriesFromProto decodes the Agent 7 v2 MetricPayload (DataDog/agent-payload metrics proto):
// series = 1 { resources 1 {type 1, name 2}, metric 2, tags 3, points 4 {value 1 double,
// timestamp 2}, type 5, interval 8 }. Unknown fields are skipped; more than MPMaxValues fields is
// ErrTooLarge.
func SeriesFromProto(b []byte) ([]Series, error) {
	budget := MPMaxValues
	var out []Series
	err := pbWalk(b, &budget, func(num protowire.Number, v []byte, _ uint64) error {
		if num != 1 {
			return nil
		}
		s := Series{}
		var typ, interval uint64
		err := pbWalk(v, &budget, func(num protowire.Number, v []byte, n uint64) error {
			switch num {
			case 1:
				var r struct{ Type, Name string }
				if err := pbWalk(v, &budget, func(num protowire.Number, v []byte, _ uint64) error {
					switch num {
					case 1:
						r.Type = string(v)
					case 2:
						r.Name = string(v)
					}
					return nil
				}); err != nil {
					return err
				}
				s.Resources = append(s.Resources, r)
			case 2:
				s.Metric = string(v)
			case 3:
				s.Tags = append(s.Tags, string(v))
			case 4:
				var p Point
				if err := pbWalk(v, &budget, func(num protowire.Number, _ []byte, n uint64) error {
					switch num {
					case 1:
						p.Val = math.Float64frombits(n)
					case 2:
						p.TS = float64(int64(n)) //nolint:gosec // int64 field
					}
					return nil
				}); err != nil {
					return err
				}
				s.Points = append(s.Points, p)
			case 5:
				typ = n
			case 8:
				interval = n
			}
			return nil
		})
		if err != nil {
			return err
		}
		s.Type = json.RawMessage(strconv.FormatUint(typ, 10))
		s.Interval = float64(int64(interval)) //nolint:gosec // int64 field
		out = append(out, s)
		return nil
	})
	return out, err
}

// pbWalk calls f for each field of one protobuf message: v is the payload of a length-delimited
// field, n the value of a varint or fixed-width field. Groups are rejected.
func pbWalk(b []byte, budget *int, f func(num protowire.Number, v []byte, n uint64) error) error {
	for len(b) > 0 {
		if *budget--; *budget < 0 {
			return ErrTooLarge
		}
		num, typ, tl := protowire.ConsumeTag(b)
		if tl < 0 {
			return ErrDatadog
		}
		b = b[tl:]
		var (
			v []byte
			n uint64
			l int
		)
		switch typ {
		case protowire.VarintType:
			n, l = protowire.ConsumeVarint(b)
		case protowire.Fixed64Type:
			n, l = protowire.ConsumeFixed64(b)
		case protowire.Fixed32Type:
			var n32 uint32
			n32, l = protowire.ConsumeFixed32(b)
			n = uint64(n32)
		case protowire.BytesType:
			v, l = protowire.ConsumeBytes(b)
		default:
			return ErrDatadog
		}
		if l < 0 {
			return ErrDatadog
		}
		b = b[l:]
		if err := f(num, v, n); err != nil {
			return err
		}
	}
	return nil
}

// DDSpanV05 expands a v0.5 span array (indices into the payload's string table) into the v0.4 map.
func DDSpanV05(dict []string, a []any) (map[string]any, bool) {
	if len(a) != 12 {
		return nil, false
	}
	str := func(v any) (string, bool) {
		i, ok := v.(uint64)
		if !ok || i >= uint64(len(dict)) {
			return "", false
		}
		return dict[i], true
	}
	m := map[string]any{
		"trace_id": a[3], "span_id": a[4], "parent_id": a[5], "start": a[6], "duration": a[7], "error": a[8],
	}
	for i, k := range map[int]string{0: "service", 1: "name", 2: "resource", 11: "type"} {
		s, ok := str(a[i])
		if !ok {
			return nil, false
		}
		m[k] = s
	}
	meta, ok1 := a[9].(map[string]any)
	metrics, ok2 := a[10].(map[string]any)
	if !ok1 || !ok2 {
		return nil, false
	}
	rm, rx := map[string]any{}, map[string]any{}
	for k, v := range meta {
		ks, ok := str(mpIdx(k))
		vs, ok3 := str(v)
		if !ok || !ok3 {
			return nil, false
		}
		rm[ks] = vs
	}
	for k, v := range metrics {
		ks, ok := str(mpIdx(k))
		if !ok {
			return nil, false
		}
		rx[ks] = v
	}
	m["meta"], m["metrics"] = rm, rx
	return m, true
}

// mpIdx undoes the decoder's stringification of integer map keys.
func mpIdx(k string) any {
	var n uint64
	for _, c := range k {
		if c < '0' || c > '9' || n > math.MaxUint32 {
			return nil
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// DDTracesV05 converts a decoded v0.5 payload [string table, traces] by expanding every span to
// the v0.4 shape and reusing DDTraces.
func DDTracesV05(v any, maxSpans int) (*colltrace.ExportTraceServiceRequest, error) {
	top, _ := v.([]any)
	if len(top) != 2 {
		return nil, ErrDatadog
	}
	rawDict, _ := top[0].([]any)
	dict := make([]string, 0, len(rawDict))
	for _, s := range rawDict {
		str, isStr := s.(string)
		if !isStr {
			return nil, ErrDatadog
		}
		dict = append(dict, str)
	}
	traces, _ := top[1].([]any)
	expanded := make([]any, 0, len(traces))
	for _, t := range traces {
		spans, _ := t.([]any)
		out := make([]any, 0, len(spans))
		for _, s := range spans {
			arr, _ := s.([]any)
			m, ok := DDSpanV05(dict, arr)
			if !ok {
				return nil, ErrDatadog
			}
			out = append(out, m)
		}
		expanded = append(expanded, out)
	}
	return DDTraces(expanded, maxSpans)
}
