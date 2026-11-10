// Package srcconv holds the decoders that turn third-party wire formats (Datadog Agent, Splunk
// HEC, MessagePack) into OTLP messages. The gateway receivers and the relay sources share it.
package srcconv

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	colllogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// NewScope appends a resource (wt.* attributes dropped) with one scope and returns that scope.
func NewScope(req *colllogs.ExportLogsServiceRequest, attrs []*commonpb.KeyValue) *logspb.ScopeLogs {
	var res []*commonpb.KeyValue
	for _, kv := range attrs {
		res = AppendKV(res, kv.Key, kv.Value)
	}
	sl := &logspb.ScopeLogs{}
	req.ResourceLogs = append(req.ResourceLogs, &logspb.ResourceLogs{
		Resource: &resourcepb.Resource{Attributes: res}, ScopeLogs: []*logspb.ScopeLogs{sl},
	})
	return sl
}

// AppendKV adds an attribute unless its key is in the reserved wt.* namespace.
func AppendKV(dst []*commonpb.KeyValue, k string, v *commonpb.AnyValue) []*commonpb.KeyValue {
	if strings.HasPrefix(k, "wt.") {
		return dst
	}
	return append(dst, &commonpb.KeyValue{Key: k, Value: v})
}

// StrVal is a string AnyValue.
func StrVal(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

// JSONVal converts a decoded JSON scalar (UseNumber) to an AnyValue; arrays become JSON text.
func JSONVal(v any) *commonpb.AnyValue {
	switch x := v.(type) {
	case string:
		return StrVal(x)
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: x}}
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: i}}
		}
		if f, err := x.Float64(); err == nil {
			return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: f}}
		}
	}
	b, _ := json.Marshal(v)
	return StrVal(string(b))
}

// Flatten turns nested JSON objects into dotted keys; null values are dropped.
func Flatten(prefix string, v any, out map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if prefix != "" {
				k = prefix + "." + k
			}
			Flatten(k, c, out)
		}
	case nil:
	default:
		out[prefix] = v
	}
}

// LogRecord builds a record; ns 0 means now.
func LogRecord(ns, now uint64, body string, attrs []*commonpb.KeyValue) *logspb.LogRecord {
	if ns == 0 {
		ns = now
	}
	return &logspb.LogRecord{TimeUnixNano: ns, ObservedTimeUnixNano: now, Body: StrVal(body), Attributes: attrs}
}

// SetSeverity fills the severity text and number from a level name.
func SetSeverity(rec *logspb.LogRecord, level string) {
	rec.SeverityText = level
	rec.SeverityNumber = map[string]logspb.SeverityNumber{
		"trace": logspb.SeverityNumber_SEVERITY_NUMBER_TRACE, "debug": logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG,
		"info": logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "warn": logspb.SeverityNumber_SEVERITY_NUMBER_WARN,
		"warning": logspb.SeverityNumber_SEVERITY_NUMBER_WARN, "error": logspb.SeverityNumber_SEVERITY_NUMBER_ERROR,
		"fatal": logspb.SeverityNumber_SEVERITY_NUMBER_FATAL, "critical": logspb.SeverityNumber_SEVERITY_NUMBER_FATAL,
	}[strings.ToLower(level)]
}

// ParseTime reads a number (scaled by unit) or an RFC 3339 string into ns; 0 when unparseable.
func ParseTime(v any, unit time.Duration) uint64 {
	var f float64
	switch x := v.(type) {
	case json.Number:
		f, _ = x.Float64()
	case string:
		if t, err := time.Parse(time.RFC3339Nano, x); err == nil && t.UnixNano() > 0 {
			return uint64(t.UnixNano())
		}
		f, _ = strconv.ParseFloat(x, 64)
	}
	if f <= 0 {
		return 0
	}
	return uint64(f * float64(unit))
}

// SortedKeys returns the keys of m in order.
func SortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// JSONLogRecord turns a JSON object into a record: the first string among bodyKeys is the body (and
// is not repeated as an attribute); every other field becomes a flattened attribute. Without a
// string body the object itself, minus wt.* keys, is the body.
func JSONLogRecord(e map[string]any, bodyKeys []string, ns, now uint64) *logspb.LogRecord {
	body, used := "", ""
	for _, k := range bodyKeys {
		if s, ok := e[k].(string); ok && s != "" {
			body, used = s, k
			break
		}
	}
	flat := map[string]any{}
	Flatten("", e, flat)
	var attrs []*commonpb.KeyValue
	for _, k := range SortedKeys(flat) {
		if k != used {
			attrs = AppendKV(attrs, k, JSONVal(flat[k]))
		}
	}
	if body == "" {
		b, _ := json.Marshal(DropWt(e))
		body = string(b)
	}
	return LogRecord(ns, now, body, attrs)
}

// DecodeObjects reads JSON objects from body: a single object, an array of objects, or NDJSON
// (numbers kept exact). Malformed input is ErrDatadog, more than max objects ErrTooLarge.
func DecodeObjects(body []byte, max int) ([]map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var out []map[string]any
	for {
		var v any
		if err := d.Decode(&v); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, ErrDatadog
		}
		switch t := v.(type) {
		case map[string]any:
			out = append(out, t)
		case []any:
			for _, x := range t {
				m, ok := x.(map[string]any)
				if !ok {
					return nil, ErrDatadog
				}
				out = append(out, m)
			}
		default:
			return nil, ErrDatadog
		}
		if len(out) > max {
			return nil, ErrTooLarge
		}
	}
}
