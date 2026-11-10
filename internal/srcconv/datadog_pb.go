package srcconv

// Datadog protobuf intake shared by the gateway and the relay: the trace-agent's /api/v0.2/traces
// AgentPayload (incl. the string-indexed v1 payload), /api/v0.2/stats, distribution sketches and
// events. Field numbers follow the public DataDog/agent-payload and datadog-agent
// pkg/proto/datadog/trace protos. The decoder is a small schema walk over protowire that yields the
// same maps the msgpack receivers produce, so DDSpan is reused unchanged.

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"time"

	colltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

type pbKind uint8

const (
	pbStr pbKind = iota
	pbUint
	pbF64
	pbMsg
	pbStrMap // map<string,string>
	pbF64Map // map<string,double>
	pbRaw    // length-delimited bytes kept undecoded (a sub-message decoded later)
)

type pbField struct {
	name string
	kind pbKind
	rep  bool
	sub  pbSchema
}

type pbSchema map[protowire.Number]pbField

var (
	// Span keys are the v0.4 msgpack names, so DDSpan reads both.
	ddSpanPB = pbSchema{
		1: {name: "service"}, 2: {name: "name"}, 3: {name: "resource"}, 4: {name: "trace_id", kind: pbUint},
		5: {name: "span_id", kind: pbUint}, 6: {name: "parent_id", kind: pbUint}, 7: {name: "start", kind: pbUint},
		8: {name: "duration", kind: pbUint}, 9: {name: "error", kind: pbUint}, 10: {name: "meta", kind: pbStrMap},
		11: {name: "metrics", kind: pbF64Map}, 12: {name: "type"},
	}
	ddChunkPB         = pbSchema{3: {name: "spans", kind: pbMsg, rep: true, sub: ddSpanPB}}
	ddTracerPayloadPB = pbSchema{
		6: {name: "chunks", kind: pbMsg, rep: true, sub: ddChunkPB}, 8: {name: "env"}, 9: {name: "hostname"}, 10: {name: "appVersion"},
	}
	ddAgentPayloadPB = pbSchema{
		1: {name: "hostName"}, 2: {name: "env"}, 5: {name: "tracerPayloads", kind: pbMsg, rep: true, sub: ddTracerPayloadPB},
		11: {name: "idxTracerPayloads", kind: pbRaw, rep: true},
	}

	// Stats keys are the Go field names the agent's msgpack encoding uses (looked up case-insensitively).
	ddGroupedStatsPB = pbSchema{
		1: {name: "Service"}, 2: {name: "Name"}, 3: {name: "Resource"}, 4: {name: "HTTPStatusCode", kind: pbUint},
		5: {name: "Type"}, 7: {name: "Hits", kind: pbUint}, 8: {name: "Errors", kind: pbUint}, 9: {name: "Duration", kind: pbUint},
		13: {name: "TopLevelHits", kind: pbUint}, 15: {name: "SpanKind"},
	}
	ddStatsBucketPB = pbSchema{
		1: {name: "Start", kind: pbUint}, 2: {name: "Duration", kind: pbUint}, 3: {name: "Stats", kind: pbMsg, rep: true, sub: ddGroupedStatsPB},
	}
	ddStatsPayloadPB = pbSchema{1: {name: "AgentHostname"}, 2: {name: "AgentEnv"}, 3: {name: "Stats", kind: pbMsg, rep: true, sub: pbSchema{
		1: {name: "Hostname"}, 2: {name: "Env"}, 3: {name: "Version"}, 4: {name: "Stats", kind: pbMsg, rep: true, sub: ddStatsBucketPB},
		10: {name: "Service"},
	}}}
)

// pw walks one message with its own field budget.
func pw(b []byte, f func(num protowire.Number, v []byte, n uint64) error) error {
	budget := MPMaxValues
	return pbWalk(b, &budget, f)
}

// pbDecode walks b by schema s; unknown fields are skipped. budget caps decoded fields per request.
func pbDecode(b []byte, s pbSchema, budget *int) (map[string]any, error) {
	out := map[string]any{}
	err := pw(b, func(num protowire.Number, v []byte, n uint64) error {
		f, ok := s[num]
		if !ok {
			return nil
		}
		if *budget--; *budget < 0 {
			return ErrTooLarge
		}
		var val any
		switch f.kind {
		case pbStr:
			val = string(v)
		case pbUint:
			val = n
		case pbF64:
			val = math.Float64frombits(n)
		case pbRaw:
			val = v
		case pbMsg:
			m, err := pbDecode(v, f.sub, budget)
			if err != nil {
				return err
			}
			val = m
		case pbStrMap, pbF64Map:
			return pbMapEntry(out, f, v)
		}
		if f.rep {
			l, _ := out[f.name].([]any)
			out[f.name] = append(l, val)
		} else {
			out[f.name] = val
		}
		return nil
	})
	return out, err
}

// pbMapEntry adds one map entry message (key = 1, value = 2) to out[f.name].
func pbMapEntry(out map[string]any, f pbField, v []byte) error {
	m, _ := out[f.name].(map[string]any)
	if m == nil {
		m = map[string]any{}
		out[f.name] = m
	}
	var (
		k   string
		val any = ""
	)
	if f.kind == pbF64Map {
		val = 0.0
	}
	err := pw(v, func(num protowire.Number, b []byte, n uint64) error {
		switch {
		case num == 1:
			k = string(b)
		case num == 2 && f.kind == pbStrMap:
			val = string(b)
		case num == 2:
			val = math.Float64frombits(n)
		}
		return nil
	})
	m[k] = val
	return err
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

func anyMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// ciGet reads k, tolerating the msgpack/proto spelling differences ("Stats" vs "stats").
func ciGet(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	for mk, v := range m {
		if strings.EqualFold(mk, k) {
			return v
		}
	}
	return nil
}

// DDTracesV02 reads the trace-agent's AgentPayload (protobuf; the caller undoes gzip or zstd).
// More than maxSpans spans is ErrTooLarge.
func DDTracesV02(body []byte, maxSpans int) (*colltrace.ExportTraceServiceRequest, error) {
	budget := MPMaxValues
	top, err := pbDecode(body, ddAgentPayloadPB, &budget)
	var payloads []map[string]any
	for _, tp := range anyList(top["tracerPayloads"]) {
		payloads = append(payloads, anyMap(tp))
	}
	// The string-indexed v1 payload decodes to the same shape.
	for _, raw := range anyList(top["idxTracerPayloads"]) {
		if err != nil {
			break
		}
		b, _ := raw.([]byte)
		var p map[string]any
		if p, err = ddIdxPayload(b, &budget); err == nil {
			payloads = append(payloads, p)
		}
	}
	g, n := newSpanGroups(), 0
	for _, p := range payloads {
		if err != nil {
			break
		}
		for k, agentKey := range map[string]string{"env": "env", "hostname": "hostName"} {
			if MPStr(p[k]) == "" {
				p[k] = top[agentKey]
			}
		}
		err = AddTracerPayload(g, p, &n, maxSpans)
	}
	if err != nil {
		return nil, err
	}
	return g.request(), nil
}

// DDTracesV07 reads the TracerPayload map {chunks:[{spans:[<v0.4 span map>]}], env, hostname, appVersion}.
func DDTracesV07(top map[string]any, maxSpans int) (*colltrace.ExportTraceServiceRequest, error) {
	g, n := newSpanGroups(), 0
	if err := AddTracerPayload(g, top, &n, maxSpans); err != nil {
		return nil, err
	}
	return g.request(), nil
}

// AddTracerPayload adds one TracerPayload's spans to g; n counts spans across the request.
func AddTracerPayload(g *spanGroups, top map[string]any, n *int, maxSpans int) error {
	var extra []*commonpb.KeyValue
	for k, attr := range map[string]string{"env": "deployment.environment", "hostname": "host.name", "appVersion": "service.version"} {
		if s := MPStr(top[k]); s != "" {
			extra = AppendKV(extra, attr, StrVal(s))
		}
	}
	chunks, _ := top["chunks"].([]any)
	for _, c := range chunks {
		chunk, _ := c.(map[string]any)
		spans, _ := chunk["spans"].([]any)
		for _, s := range spans {
			m, isMap := s.(map[string]any)
			if !isMap {
				return ErrDatadog
			}
			if *n++; *n > maxSpans {
				return ErrTooLarge
			}
			sp, svc := DDSpan(m)
			g.add(svc, extra, sp)
		}
	}
	return nil
}

// ---- string-indexed v1 payload ----
//
// TracerPayload: strings 1, envRef 7, hostnameRef 8, appVersionRef 9, chunks 11
// TraceChunk:    spans 4, traceID 6 (128-bit, big endian)
// Span:          serviceRef 1, nameRef 2, resourceRef 3, spanID 4, parentID 5, start 6,
//                duration 7, error 8, attributes 9, typeRef 10, kind 16
// attributes:    map<uint32 key ref, AnyValue>; AnyValue: stringValueRef 1, boolValue 2,
//                doubleValue 3, intValue 4
//
// shortcut: span links and events, the span `kind` enum, chunk attributes and the env, version and
// component refs of a span are not mapped (the payload-level env and app version are). An index
// outside the table fails the request with ErrDatadog rather than guessing, so a field-number
// drift in a newer agent shows up loudly; verify against a captured payload when the agent
// default changes.

type ddIdx struct {
	table []string
	bad   bool
}

func (x *ddIdx) str(ref uint64) string {
	if ref == 0 {
		return "" // index 0 is the empty string, whether or not the table lists it
	}
	if ref >= uint64(len(x.table)) {
		x.bad = true
		return ""
	}
	return x.table[ref]
}

func ddIdxPayload(b []byte, budget *int) (map[string]any, error) {
	x := &ddIdx{}
	var chunks [][]byte
	refs := map[protowire.Number]uint64{}
	err := pw(b, func(num protowire.Number, v []byte, n uint64) error {
		if *budget--; *budget < 0 {
			return ErrTooLarge
		}
		switch num {
		case 1:
			x.table = append(x.table, string(v))
		case 7, 8, 9:
			refs[num] = n
		case 11:
			chunks = append(chunks, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{"env": x.str(refs[7]), "hostname": x.str(refs[8]), "appVersion": x.str(refs[9])}
	var outChunks []any
	for _, c := range chunks {
		spans, err := x.chunk(c, budget)
		if err != nil {
			return nil, err
		}
		outChunks = append(outChunks, map[string]any{"spans": spans})
	}
	out["chunks"] = outChunks
	if x.bad {
		return nil, ErrDatadog
	}
	return out, nil
}

func (x *ddIdx) chunk(b []byte, budget *int) ([]any, error) {
	var (
		spans [][]byte
		tid   []byte
	)
	err := pw(b, func(num protowire.Number, v []byte, _ uint64) error {
		switch num {
		case 4:
			spans = append(spans, v)
		case 6:
			tid = v
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(spans))
	for _, s := range spans {
		m, err := x.span(s, tid, budget)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (x *ddIdx) span(b, traceID []byte, budget *int) (map[string]any, error) {
	m := map[string]any{"trace_id": uint64(0)}
	meta, metrics := map[string]any{}, map[string]any{}
	if len(traceID) == 16 {
		m["trace_id"] = binary.BigEndian.Uint64(traceID[8:])
		if hi := binary.BigEndian.Uint64(traceID[:8]); hi != 0 {
			meta["_dd.p.tid"] = hex.EncodeToString(traceID[:8])
		}
	}
	err := pw(b, func(num protowire.Number, v []byte, n uint64) error {
		if *budget--; *budget < 0 {
			return ErrTooLarge
		}
		switch num {
		case 1:
			m["service"] = x.str(n)
		case 2:
			m["name"] = x.str(n)
		case 3:
			m["resource"] = x.str(n)
		case 4:
			m["span_id"] = n
		case 5:
			m["parent_id"] = n
		case 6:
			m["start"] = n
		case 7:
			m["duration"] = n
		case 8:
			m["error"] = n
		case 10:
			m["type"] = x.str(n)
		case 9:
			return x.attr(v, meta, metrics)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	m["meta"], m["metrics"] = meta, metrics
	return m, nil
}

// attr adds one attributes map entry: strings and bools go to meta, numbers to metrics.
func (x *ddIdx) attr(entry []byte, meta, metrics map[string]any) error {
	var (
		key  string
		have bool
		val  []byte
	)
	err := pw(entry, func(num protowire.Number, v []byte, n uint64) error {
		switch num {
		case 1:
			key, have = x.str(n), true
		case 2:
			val = v
		}
		return nil
	})
	if err != nil || !have {
		return err
	}
	return pw(val, func(num protowire.Number, _ []byte, n uint64) error {
		switch num {
		case 1:
			meta[key] = x.str(n)
		case 2:
			meta[key] = map[bool]string{true: "true", false: "false"}[n != 0]
		case 3:
			metrics[key] = math.Float64frombits(n)
		case 4:
			metrics[key] = float64(int64(n)) //nolint:gosec // two's complement int64 field
		}
		return nil
	})
}

// ---- stats ----

// DDStatsMetrics maps the trace-agent's APM stats (msgpack when isMsgpack, else protobuf) to delta
// counters: dd.trace.hits, .errors, .top_level_hits and .duration_ns per service/operation/resource.
// More than maxPoints points is ErrTooLarge.
func DDStatsMetrics(body []byte, isMsgpack bool, maxPoints int) ([]*metricspb.Metric, error) {
	var (
		top map[string]any
		err error
	)
	if isMsgpack {
		var v any
		v, err = MsgpackDecode(body)
		if top = anyMap(v); err == nil && top == nil {
			err = ErrDatadog
		}
	} else {
		budget := MPMaxValues
		top, err = pbDecode(body, ddStatsPayloadPB, &budget)
	}
	if err != nil {
		return nil, err
	}
	names := []string{"dd.trace.hits", "dd.trace.errors", "dd.trace.top_level_hits", "dd.trace.duration_ns"}
	keys := map[string]string{"dd.trace.hits": "Hits", "dd.trace.errors": "Errors", "dd.trace.top_level_hits": "TopLevelHits", "dd.trace.duration_ns": "Duration"}
	sums := map[string]*metricspb.Sum{}
	points := 0
	for _, c := range anyList(ciGet(top, "Stats")) {
		cp := anyMap(c)
		var base []*commonpb.KeyValue
		for attr, ks := range map[string][2]string{
			"host.name": {"Hostname", "AgentHostname"}, "deployment.environment": {"Env", "AgentEnv"}, "service.version": {"Version", ""},
		} {
			v := MPStr(ciGet(cp, ks[0]))
			if v == "" && ks[1] != "" {
				v = MPStr(ciGet(top, ks[1]))
			}
			if v != "" {
				base = AppendKV(base, attr, StrVal(v))
			}
		}
		sort.Slice(base, func(i, j int) bool { return base[i].Key < base[j].Key })
		for _, b := range anyList(ciGet(cp, "Stats")) {
			bm := anyMap(b)
			start := MPU64(ciGet(bm, "Start"))
			end := start + MPU64(ciGet(bm, "Duration"))
			for _, gs := range anyList(ciGet(bm, "Stats")) {
				gm := anyMap(gs)
				if points >= maxPoints {
					return nil, ErrTooLarge
				}
				attrs := ddStatsAttrs(base, gm)
				for _, name := range names {
					sm := sums[name]
					if sm == nil {
						sm = &metricspb.Sum{IsMonotonic: true, AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA}
						sums[name] = sm
					}
					p := &metricspb.NumberDataPoint{
						TimeUnixNano: end, Attributes: attrs,
						Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: float64(MPU64(ciGet(gm, keys[name])))},
					}
					if start < end {
						p.StartTimeUnixNano = start
					}
					sm.DataPoints = append(sm.DataPoints, p)
					points++
				}
			}
		}
	}
	var out []*metricspb.Metric
	for _, name := range names {
		if sm := sums[name]; sm != nil {
			out = append(out, &metricspb.Metric{Name: name, Data: &metricspb.Metric_Sum{Sum: sm}})
		}
	}
	return out, nil
}

func ddStatsAttrs(base []*commonpb.KeyValue, gm map[string]any) []*commonpb.KeyValue {
	attrs := append([]*commonpb.KeyValue(nil), base...)
	for _, kv := range [][2]string{
		{"service.name", "Service"}, {"span.name", "Name"}, {"resource.name", "Resource"}, {"dd.span.type", "Type"}, {"span.kind", "SpanKind"},
	} {
		if v := MPStr(ciGet(gm, kv[1])); v != "" {
			attrs = AppendKV(attrs, kv[0], StrVal(v))
		}
	}
	if code := MPU64(ciGet(gm, "HTTPStatusCode")); code != 0 {
		attrs = AppendKV(attrs, "http.response.status_code", &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(code)}}) //nolint:gosec // uint32 field
	}
	return attrs
}

// ---- events ----

// DDTagList reads a JSON array of tag strings.
func DDTagList(v any) []string {
	var out []string
	if arr, ok := v.([]any); ok {
		for _, t := range arr {
			if s, ok := t.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// TagAttrs turns "k:v" tags (a bare tag is "true") into attributes.
func TagAttrs(attrs []*commonpb.KeyValue, tags []string) []*commonpb.KeyValue {
	for _, t := range tags {
		k, v, found := strings.Cut(t, ":")
		if k == "" {
			continue
		}
		if !found {
			v = "true"
		}
		attrs = AppendKV(attrs, k, StrVal(v))
	}
	return attrs
}

// DDEventLog maps one event to a log record (severity from alert_type), tagged `datadog.event = true`
// with the event fields under `datadog.event.*`.
func DDEventLog(e map[string]any, now uint64) *logspb.LogRecord {
	title, _ := e["title"].(string)
	text, _ := e["text"].(string)
	body := title
	if title == "" || text != "" {
		body = strings.TrimPrefix(title+"\n"+text, "\n")
	}
	attrs := AppendKV(nil, "datadog.event", StrVal("true"))
	if v, _ := e["host"].(string); v != "" {
		attrs = AppendKV(attrs, "host.name", StrVal(v))
	}
	for _, k := range []string{"alert_type", "priority", "aggregation_key", "source_type_name", "device_name"} {
		if v, _ := e[k].(string); v != "" {
			attrs = AppendKV(attrs, "datadog.event."+k, StrVal(v))
		}
	}
	attrs = TagAttrs(attrs, DDTagList(e["tags"]))
	rec := LogRecord(ParseTime(e["date_happened"], time.Second), now, body, attrs)
	level, _ := e["alert_type"].(string)
	SetSeverity(rec, map[string]string{"error": "error", "warning": "warn"}[level])
	if rec.SeverityText == "" {
		SetSeverity(rec, "info")
	}
	return rec
}

// ---- sketches ----
