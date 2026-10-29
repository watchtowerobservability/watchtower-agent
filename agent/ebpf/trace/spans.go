package trace

import (
	"crypto/rand"
	"sync"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// Span is one observed request. TraceID is random unless a traceparent header supplied it;
// ParentID is set only from a traceparent, never synthesized.
type Span struct {
	Name       string
	Client     bool // CLIENT, otherwise SERVER
	Start, End time.Time
	TraceID    [16]byte
	SpanID     [8]byte
	ParentID   [8]byte
	HasParent  bool
	Error      bool
	Attrs      map[string]any // string, int64 only
	PID        uint32
}

func newID(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
}

func attr(k string, v any) *commonpb.KeyValue {
	kv := &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{}}
	switch x := v.(type) {
	case int64:
		kv.Value.Value = &commonpb.AnyValue_IntValue{IntValue: x}
	case string:
		kv.Value.Value = &commonpb.AnyValue_StringValue{StringValue: x}
	}
	return kv
}

// Proto converts the span to OTLP, tagged wt-ebpf. Attributes are sorted by the caller's map
// order being irrelevant: OTLP attributes are an unordered set.
func (s Span) Proto() *tracepb.Span {
	kind := tracepb.Span_SPAN_KIND_SERVER
	if s.Client {
		kind = tracepb.Span_SPAN_KIND_CLIENT
	}
	p := &tracepb.Span{
		TraceId: s.TraceID[:], SpanId: s.SpanID[:], Name: s.Name, Kind: kind,
		StartTimeUnixNano: uint64(s.Start.UnixNano()), EndTimeUnixNano: uint64(s.End.UnixNano()),
		Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_UNSET},
	}
	if s.HasParent {
		p.ParentSpanId = s.ParentID[:]
	}
	if s.Error {
		p.Status.Code = tracepb.Status_STATUS_CODE_ERROR
	}
	for k, v := range s.Attrs {
		p.Attributes = append(p.Attributes, attr(k, v))
	}
	p.Attributes = append(p.Attributes, attr("wt.instrumentation", "ebpf"), attr("telemetry.sdk.name", "wt-ebpf"))
	return p
}

// Limiter caps events per second; events over the cap are dropped and counted.
type Limiter struct {
	mu      sync.Mutex
	max     int
	sec     int64
	n       int
	dropped uint64
}

// NewLimiter returns a limiter for max events per second (<= 0 means 20000).
func NewLimiter(max int) *Limiter {
	if max <= 0 {
		max = 20_000
	}
	return &Limiter{max: max}
}

// Allow reports whether an event at t fits the current second.
func (l *Limiter) Allow(t time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := t.Unix(); s != l.sec {
		l.sec, l.n = s, 0
	}
	if l.n >= l.max {
		l.dropped++
		return false
	}
	l.n++
	return true
}

// Dropped is the number of events refused so far.
func (l *Limiter) Dropped() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}
