package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// A Parallel state with two branches, a Lambda task that fails inside one, and a failed execution.
const sfnHistory = `{"events":[
 {"id":1,"previousEventId":0,"type":"ExecutionStarted","timestamp":100.0,"executionStartedEventDetails":{}},
 {"id":2,"previousEventId":1,"type":"ParallelStateEntered","timestamp":100.1,"stateEnteredEventDetails":{"name":"Fan"}},
 {"id":3,"previousEventId":2,"type":"ParallelStateStarted","timestamp":100.1},
 {"id":4,"previousEventId":3,"type":"TaskStateEntered","timestamp":100.2,"stateEnteredEventDetails":{"name":"Charge"}},
 {"id":5,"previousEventId":3,"type":"PassStateEntered","timestamp":100.2,"stateEnteredEventDetails":{"name":"Note"}},
 {"id":6,"previousEventId":4,"type":"TaskScheduled","timestamp":100.3,"taskScheduledEventDetails":{"resource":"invoke","resourceType":"lambda"}},
 {"id":7,"previousEventId":5,"type":"PassStateExited","timestamp":100.4,"stateExitedEventDetails":{"name":"Note"}},
 {"id":8,"previousEventId":6,"type":"TaskFailed","timestamp":101.0,"taskFailedEventDetails":{"error":"Card.Declined","cause":"declined"}},
 {"id":9,"previousEventId":8,"type":"TaskStateExited","timestamp":101.1,"stateExitedEventDetails":{"name":"Charge"}},
 {"id":10,"previousEventId":9,"type":"ParallelStateFailed","timestamp":101.2},
 {"id":11,"previousEventId":10,"type":"ParallelStateExited","timestamp":101.2,"stateExitedEventDetails":{"name":"Fan"}},
 {"id":12,"previousEventId":11,"type":"PassStateEntered","timestamp":101.3,"stateEnteredEventDetails":{"name":"After"}},
 {"id":13,"previousEventId":12,"type":"ExecutionFailed","timestamp":101.5,"executionFailedEventDetails":{"error":"States.TaskFailed","cause":"branch failed"}}
]}`

func sfnSpanByName(spans []*tracepb.Span, name string) *tracepb.Span {
	for _, s := range spans {
		if s.GetName() == name {
			return s
		}
	}
	return nil
}

func sfnAttr(s *tracepb.Span, k string) string {
	for _, a := range s.GetAttributes() {
		if a.GetKey() == k {
			return a.GetValue().GetStringValue()
		}
	}
	return ""
}

func TestExecutionHistoryBecomesASpanTree(t *testing.T) {
	var h struct {
		Events []sfnEvent `json:"events"`
	}
	if err := json.Unmarshal([]byte(sfnHistory), &h); err != nil {
		t.Fatal(err)
	}
	x := sfnExecution{ExecutionArn: "arn:aws:states:eu-west-1:1:execution:orders:run-1", StateMachineArn: "arn:aws:states:eu-west-1:1:stateMachine:orders",
		Name: "run-1", Status: "FAILED", StartDate: 100, StopDate: 101.5}
	spans := executionSpans(x, h.Events)
	if len(spans) != 6 { // execution, Fan, Charge, Note, lambda task, After
		t.Fatalf("%d spans", len(spans))
	}
	root, fan, charge, note := spans[0], sfnSpanByName(spans, "Fan"), sfnSpanByName(spans, "Charge"), sfnSpanByName(spans, "Note")
	task, after := sfnSpanByName(spans, "lambda invoke"), sfnSpanByName(spans, "After")
	for _, s := range spans {
		if string(s.GetTraceId()) != string(root.GetTraceId()) || len(s.GetTraceId()) != 16 || len(s.GetSpanId()) != 8 {
			t.Fatalf("ids of %s", s.GetName())
		}
	}
	parent := func(s, p *tracepb.Span) {
		t.Helper()
		if string(s.GetParentSpanId()) != string(p.GetSpanId()) {
			t.Errorf("%s is not a child of %s", s.GetName(), p.GetName())
		}
	}
	parent(fan, root)
	parent(charge, fan)
	parent(note, fan) // concurrent branch, paired by previousEventId
	parent(task, charge)
	parent(after, root)
	if note.GetEndTimeUnixNano() != sfnNanos(100.4) || charge.GetEndTimeUnixNano() != sfnNanos(101.1) {
		t.Errorf("state ends: note %d charge %d", note.GetEndTimeUnixNano(), charge.GetEndTimeUnixNano())
	}
	if task.GetKind() != tracepb.Span_SPAN_KIND_CLIENT || task.GetStatus().GetCode() != tracepb.Status_STATUS_CODE_ERROR ||
		sfnAttr(task, "error.type") != "Card.Declined" || task.GetEndTimeUnixNano() != sfnNanos(101.0) {
		t.Errorf("task span: %v", task)
	}
	if root.GetStatus().GetCode() != tracepb.Status_STATUS_CODE_ERROR || root.GetStatus().GetMessage() != "branch failed" ||
		sfnAttr(root, "error.type") != "States.TaskFailed" || sfnAttr(fan, "aws.stepfunctions.state_type") != "Parallel" {
		t.Errorf("root: %v", root)
	}
	if after.GetEndTimeUnixNano() != sfnNanos(101.5) { // never exited: ends with the execution
		t.Errorf("after ends %d", after.GetEndTimeUnixNano())
	}
}

func TestPollerSendsEachFinishedExecutionOnce(t *testing.T) {
	now := time.Unix(1_000, 0)
	calls := map[string]int{}
	call := func(_ context.Context, op string, in, out any) error {
		calls[op]++
		var body string
		switch op {
		case "ListStateMachines":
			body = `{"stateMachines":[{"stateMachineArn":"arn:aws:states:r:1:stateMachine:orders","type":"STANDARD"},
				{"stateMachineArn":"arn:aws:states:r:1:stateMachine:fast","type":"EXPRESS"}]}`
		case "ListExecutions":
			if in.(map[string]any)["stateMachineArn"] != "arn:aws:states:r:1:stateMachine:orders" {
				return errors.New("an express machine was listed")
			}
			body = `{"executions":[{"executionArn":"e-done","status":"SUCCEEDED","startDate":990,"stopDate":995},
				{"executionArn":"e-running","status":"RUNNING","startDate":998},
				{"executionArn":"e-old","status":"SUCCEEDED","startDate":1,"stopDate":2}]}`
		case "GetExecutionHistory":
			body = `{"events":[{"id":1,"previousEventId":0,"type":"ExecutionStarted","timestamp":990},
				{"id":2,"previousEventId":1,"type":"ExecutionSucceeded","timestamp":995}]}`
		}
		return json.Unmarshal([]byte(body), out)
	}
	var sent []map[string]string
	rec := &sink.Recorder{}
	p := newSFNPoller(SFNConfig{}, call, func(res map[string]string, spans []*tracepb.Span) { sent = append(sent, res) }, rec)
	p.region = "r"
	p.poll(context.Background(), now)
	p.poll(context.Background(), now.Add(time.Minute))
	if len(sent) != 1 || sent[0]["service.name"] != "orders" || sent[0]["cloud.region"] != "r" || calls["GetExecutionHistory"] != 1 {
		t.Fatalf("sent %v, calls %v", sent, calls)
	}
	failing := newSFNPoller(SFNConfig{StateMachines: []string{"m"}}, func(context.Context, string, any, any) error {
		return errors.New("stepfunctions ListExecutions: HTTP 400 AccessDeniedException")
	}, nil, rec)
	failing.poll(context.Background(), now)
	failing.poll(context.Background(), now)
	logs := 0
	for _, s := range rec.Snapshot() {
		if s.Body != "" {
			logs++
		}
	}
	if logs != 1 {
		t.Errorf("the same error must be logged once, got %d", logs)
	}
}

func TestStepFunctionsIsInertUnlessEnabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	called := false
	if err := RunStepFunctions(ctx, json.RawMessage(`{"region":"eu-west-1"}`), &sink.Recorder{}, func(map[string]string, []*tracepb.Span) { called = true }); err != nil || called {
		t.Fatalf("err %v, called %v", err, called)
	}
}
