package cloud

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// sfnEvent is one execution history event. Details sit under a type-specific key
// (stateEnteredEventDetails, taskFailedEventDetails, ...), kept raw and read on demand.
type sfnEvent struct {
	ID        int64   `json:"id"`
	Prev      int64   `json:"previousEventId"`
	Type      string  `json:"type"`
	Timestamp float64 `json:"timestamp"`
	// detail is the event's *EventDetails object.
	detail map[string]any
}

func (e *sfnEvent) UnmarshalJSON(b []byte) error {
	type plain sfnEvent
	if err := json.Unmarshal(b, (*plain)(e)); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for k, v := range all {
		if strings.HasSuffix(k, "EventDetails") {
			_ = json.Unmarshal(v, &e.detail)
			break
		}
	}
	return nil
}

func (e *sfnEvent) str(field string) string {
	s, _ := e.detail[field].(string)
	return s
}

const sfnCauseMax = 500

func sfnTaskStart(t string) bool {
	return t == "TaskScheduled" || t == "LambdaFunctionScheduled" || t == "ActivityScheduled"
}

func sfnTaskEnd(t string) bool {
	for _, p := range []string{"Task", "LambdaFunction", "Activity"} {
		if rest, ok := strings.CutPrefix(t, p); ok {
			switch rest {
			case "Succeeded", "Failed", "TimedOut", "StartFailed", "ScheduleFailed", "SubmitFailed":
				return true
			}
		}
	}
	return false
}

func sfnFailed(t string) bool {
	return strings.HasSuffix(t, "Failed") || strings.HasSuffix(t, "TimedOut") || strings.HasSuffix(t, "Aborted")
}

func sfnTraceID(arn string) []byte {
	h := sha256.Sum256([]byte("sfn:" + arn))
	return h[:16]
}

func sfnSpanID(arn string, event int64) []byte {
	h := sha256.Sum256([]byte(arn + "#" + sfnItoa(event)))
	return h[:8]
}

func sfnItoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func sfnKV(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func sfnNanos(s float64) uint64 { return uint64(s * 1e9) } //nolint:gosec // epoch seconds after 1970

func sfnEntered(e *sfnEvent) bool { return strings.HasSuffix(e.Type, "StateEntered") }

// back walks the previousEventId chain from e (exclusive) and returns the first event ok accepts.
func sfnBack(byID map[int64]*sfnEvent, e *sfnEvent, ok func(*sfnEvent) bool) *sfnEvent {
	for p, n := e.Prev, 0; p != 0 && n < 100_000; n++ {
		c := byID[p]
		if c == nil {
			return nil
		}
		if ok(c) {
			return c
		}
		p = c.Prev
	}
	return nil
}

// executionSpans maps an execution and its history to spans: the execution is the root; each
// state (from its *StateEntered to its *StateExited) is a child of the state that encloses it
// (Parallel, Map) or of the root; each task, Lambda or activity call is a client span inside its
// state. Matching follows previousEventId, so concurrent branches and Map iterations pair right.
func executionSpans(x sfnExecution, events []sfnEvent) []*tracepb.Span {
	arn, trace := x.ExecutionArn, sfnTraceID(x.ExecutionArn)
	slices.SortFunc(events, func(a, b sfnEvent) int { return cmp.Compare(a.ID, b.ID) })
	byID := make(map[int64]*sfnEvent, len(events))
	last := x.StopDate
	for i := range events {
		byID[events[i].ID] = &events[i]
		last = max(last, events[i].Timestamp)
	}
	root := &tracepb.Span{
		TraceId: trace, SpanId: sfnSpanID(arn, 0), Name: x.Name, Kind: tracepb.Span_SPAN_KIND_INTERNAL,
		StartTimeUnixNano: sfnNanos(x.StartDate), EndTimeUnixNano: sfnNanos(last),
		Attributes: []*commonpb.KeyValue{sfnKV("aws.stepfunctions.execution_arn", arn),
			sfnKV("aws.stepfunctions.state_machine_arn", x.StateMachineArn), sfnKV("aws.stepfunctions.status", x.Status)},
		Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_OK},
	}
	if x.Status != "SUCCEEDED" {
		root.Status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: x.Status}
	}
	exitOf := map[int64]*sfnEvent{} // StateEntered id -> its StateExited
	endOf := map[int64]*sfnEvent{}  // task start id -> its end
	for i := range events {
		e := &events[i]
		switch {
		case strings.HasSuffix(e.Type, "StateExited"):
			name := e.str("name")
			if in := sfnBack(byID, e, func(c *sfnEvent) bool {
				return sfnEntered(c) && c.str("name") == name && exitOf[c.ID] == nil
			}); in != nil {
				exitOf[in.ID] = e
			}
		case sfnTaskEnd(e.Type):
			if st := sfnBack(byID, e, func(c *sfnEvent) bool { return sfnTaskStart(c.Type) && endOf[c.ID] == nil }); st != nil {
				endOf[st.ID] = e
			}
		case sfnFailed(e.Type) && strings.HasPrefix(e.Type, "Execution"):
			root.Attributes = append(root.Attributes, sfnKV("error.type", e.str("error")))
			root.Status.Message = sink.Truncate(e.str("cause"), sfnCauseMax)
		}
	}
	// encl is the innermost state still open at an event (nil: the execution itself). States
	// nest, so it is the previous event's state, or the first of that state's own enclosing
	// states that has not exited yet.
	encl := map[int64]*sfnEvent{}
	openAt := func(c, e *sfnEvent) bool {
		ex := exitOf[c.ID]
		return ex == nil || ex.ID > e.ID
	}
	spans := []*tracepb.Span{root}
	for i := range events {
		e := &events[i]
		var cand *sfnEvent
		if c := byID[e.Prev]; c != nil {
			cand = encl[c.ID]
			if sfnEntered(c) {
				cand = c
			}
		}
		for cand != nil && !openAt(cand, e) {
			cand = encl[cand.ID]
		}
		encl[e.ID] = cand
		parent := sfnSpanID(arn, 0)
		if cand != nil {
			parent = sfnSpanID(arn, cand.ID)
		}
		switch {
		case sfnEntered(e):
			s := sfnChild(trace, sfnSpanID(arn, e.ID), parent, e.str("name"), tracepb.Span_SPAN_KIND_INTERNAL, e, exitOf[e.ID], last)
			s.Attributes = append(s.Attributes, sfnKV("aws.stepfunctions.state_type", strings.TrimSuffix(e.Type, "StateEntered")))
			spans = append(spans, s)
		case sfnTaskStart(e.Type):
			res, kind := e.str("resource"), e.str("resourceType")
			if e.Type == "LambdaFunctionScheduled" {
				kind = "lambda"
			} else if e.Type == "ActivityScheduled" {
				kind = "activity"
			}
			name := kind
			if res != "" {
				name += " " + res[strings.LastIndex(res, ":")+1:]
			}
			s := sfnChild(trace, sfnSpanID(arn, e.ID), parent, name, tracepb.Span_SPAN_KIND_CLIENT, e, endOf[e.ID], last)
			s.Attributes = append(s.Attributes, sfnKV("aws.stepfunctions.resource_type", kind), sfnKV("aws.stepfunctions.resource", res))
			spans = append(spans, s)
		}
	}
	return spans
}

// child is a span from start to end (or to the end of the trace while it never ended); an end
// event that failed marks it as an error with the error name and cause.
func sfnChild(trace, id, parent []byte, name string, kind tracepb.Span_SpanKind, start, end *sfnEvent, last float64) *tracepb.Span {
	s := &tracepb.Span{TraceId: trace, SpanId: id, ParentSpanId: parent, Name: name, Kind: kind,
		StartTimeUnixNano: sfnNanos(start.Timestamp), EndTimeUnixNano: sfnNanos(last),
		Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_UNSET}}
	if end == nil {
		return s
	}
	s.EndTimeUnixNano = sfnNanos(end.Timestamp)
	if sfnFailed(end.Type) {
		s.Status = &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: sink.Truncate(end.str("cause"), sfnCauseMax)}
		s.Attributes = append(s.Attributes, sfnKV("error.type", end.str("error")))
	}
	return s
}
