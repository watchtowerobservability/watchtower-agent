package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

type vecRec struct {
	Body     string            `json:"body"`
	Attrs    map[string]string `json:"attrs"`
	Resource map[string]string `json:"resource"`
	TraceID  *string           `json:"trace_id"`
}

type vecCase struct {
	Name   string   `json:"name"`
	Stages []Stage  `json:"stages"`
	Input  []vecRec `json:"input"`
	Output []vecRec `json:"output"`
}

func kvs(m map[string]string) []*commonpb.KeyValue {
	var out []*commonpb.KeyValue
	for k, v := range m {
		out = append(out, &commonpb.KeyValue{Key: k, Value: strVal(v)})
	}
	return out
}

func toMap(kv []*commonpb.KeyValue) map[string]string {
	out := map[string]string{}
	for _, x := range kv {
		if !strings.HasPrefix(x.Key, "wt.") {
			s, _ := strOf(x.Value)
			out[x.Key] = s
		}
	}
	return out
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func TestRelayProcessorsMatchVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/pipeline_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []vecCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Cases {
		p, err := Compile(ProcessorConfig{Version: 1, Stages: c.Stages})
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		// all records share one resource per vector record, like separate ResourceLogs
		req := &collogs.ExportLogsServiceRequest{}
		for _, in := range c.Input {
			lr := &logspb.LogRecord{Body: strVal(in.Body), Attributes: kvs(in.Attrs)}
			if in.TraceID != nil {
				lr.TraceId, _ = hex.DecodeString(*in.TraceID)
			}
			req.ResourceLogs = append(req.ResourceLogs, &logspb.ResourceLogs{
				Resource:  &resourcepb.Resource{Attributes: kvs(in.Resource)},
				ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{lr}}},
			})
		}
		p.Logs(req)
		var got []vecRec
		for _, rl := range req.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					body, _ := strOf(lr.Body)
					r := vecRec{Body: body, Attrs: toMap(lr.Attributes), Resource: toMap(rl.Resource.Attributes)}
					if len(lr.TraceId) == 16 {
						h := hex.EncodeToString(lr.TraceId)
						r.TraceID = &h
					}
					got = append(got, r)
				}
			}
		}
		if len(got) != len(c.Output) {
			t.Fatalf("%s: got %d records, want %d", c.Name, len(got), len(c.Output))
		}
		for i, w := range c.Output {
			g := got[i]
			same := g.Body == w.Body && equalMaps(g.Attrs, w.Attrs) && equalMaps(g.Resource, w.Resource) &&
				(g.TraceID == nil) == (w.TraceID == nil) && (g.TraceID == nil || *g.TraceID == *w.TraceID)
			if !same {
				t.Errorf("%s[%d]: got %+v, want %+v", c.Name, i, g, w)
			}
		}
	}
}

func TestCompileRejectsWhatRustRejects(t *testing.T) {
	for name, s := range map[string]Stage{
		"unknown":    {Type: "parse_json"},
		"rate":       {Type: "sample", Rate: 1.5, By: "trace_id"},
		"by":         {Type: "sample", Rate: 0.5, By: ""},
		"enrich_wt":  {Type: "enrich", Set: map[string]string{"wt.x": "1"}},
		"bad_regex":  {Type: "redact", Patterns: []string{"("}},
		"no_drop_if": {Type: "filter"},
	} {
		if _, err := Compile(ProcessorConfig{Version: 1, Stages: []Stage{s}}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestQueueSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	q, err := OpenQueue(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"one", "two", "three"} {
		if err := q.Add("/v1/logs", []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	_ = q.Close()
	q, err = OpenQueue(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if q.Depth() != 3 {
		t.Fatalf("depth after restart = %d, want 3", q.Depth())
	}
	var got []string
	if err := q.Drain(func(path string, body []byte) error {
		got = append(got, path+":"+string(body))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "/v1/logs:one,/v1/logs:two,/v1/logs:three" || q.Depth() != 0 {
		t.Fatalf("drained %v, depth %d", got, q.Depth())
	}
}

func TestQueueFullDropsOldestAndCounts(t *testing.T) {
	q, err := OpenQueue(t.TempDir(), 1<<20) // far below one 16 MiB segment: older segments go
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	blob := make([]byte, 5<<20) // three per segment
	for i := 0; i < 7; i++ {
		blob[0] = byte(i)
		if err := q.Add("/v1/traces", blob); err != nil {
			t.Fatal(err)
		}
	}
	if q.Dropped() != 6 {
		t.Fatalf("dropped = %d, want 6 (two full segments)", q.Dropped())
	}
	if q.Depth() != 1 {
		t.Fatalf("depth = %d, want 1", q.Depth())
	}
	var first byte = 255
	_ = q.Drain(func(_ string, body []byte) error { first = body[0]; return nil })
	if first != 6 {
		t.Fatalf("oldest surviving batch = %d, want 6", first)
	}
}

func TestRetryAfterHonored(t *testing.T) {
	var calls atomic.Int32
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wti_key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer gw.Close()
	q, err := OpenQueue(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	_ = q.Add("/v1/logs", []byte("x"))
	f := &Forwarder{Q: q, Upstream: gw.URL, Key: "wti_key", HTTP: gw.Client()}
	wait, err := f.Step(context.Background())
	if err == nil || wait != 7*time.Second {
		t.Fatalf("first step: wait=%v err=%v, want 7s and an error", wait, err)
	}
	if q.Depth() != 1 {
		t.Fatalf("batch must stay queued, depth=%d", q.Depth())
	}
	if wait, err = f.Step(context.Background()); err != nil || wait != 0 || q.Depth() != 0 || f.Forwarded.Load() != 1 {
		t.Fatalf("second step: wait=%v err=%v depth=%d", wait, err, q.Depth())
	}
}

func TestRejectedBatchIsDroppedAndCounted(t *testing.T) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) }))
	defer gw.Close()
	q, _ := OpenQueue(t.TempDir(), 0)
	defer q.Close()
	_ = q.Add("/v1/logs", []byte("x"))
	f := &Forwarder{Q: q, Upstream: gw.URL, Key: "k", HTTP: gw.Client()}
	if _, err := f.Step(context.Background()); err != nil || f.Rejected.Load() != 1 || q.Depth() != 0 {
		t.Fatalf("err=%v rejected=%d depth=%d", err, f.Rejected.Load(), q.Depth())
	}
}

func TestSameTraceSameRelay(t *testing.T) {
	nodes := []string{"http://r1:4318", "http://r2:4318", "http://r3:4318"}
	a := NewPeers(nodes[0], "s", nodes[1:])
	b := NewPeers(nodes[2], "s", []string{nodes[0], nodes[1]}) // different self and order
	spread := map[string]int{}
	for i := 1; i <= 200; i++ { // an all-zero trace id is invalid and stays on the receiving relay
		id := make([]byte, 16)
		id[0], id[15] = byte(i), byte(i*7)
		if a.Owner(id) != b.Owner(id) {
			t.Fatalf("relays disagree on the owner of trace %x", id)
		}
		spread[a.Owner(id)]++
	}
	if len(spread) != 3 {
		t.Fatalf("traces not spread over all relays: %v", spread)
	}

	// spans of one trace stay in one part, whatever resource or scope they came in
	id := make([]byte, 16)
	id[15] = 9
	req := &coltrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{
		{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{TraceId: id, Name: "a"}, {TraceId: id, Name: "b"}}}}},
		{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{TraceId: id, Name: "c"}}}}},
	}}
	parts := SplitTraces(req, a.Owner)
	if len(parts) != 1 || parts[a.Owner(id)] == nil {
		t.Fatalf("one trace must map to one owner, got %d parts", len(parts))
	}
}

func TestProcessedTracesDropUnsampledAndWT(t *testing.T) {
	p, err := Compile(ProcessorConfig{Version: 1, Stages: []Stage{{Type: "sample", Rate: 0.5, By: "trace_id"}}})
	if err != nil {
		t.Fatal(err)
	}
	keep := make([]byte, 16)
	keep[15] = 1
	drop := make([]byte, 16)
	for i := 8; i < 16; i++ {
		drop[i] = 0xff
	}
	req := &coltrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{
		{TraceId: keep, Name: "k", Attributes: kvs(map[string]string{"wt.tenant": "x", "a": "b"})},
		{TraceId: drop, Name: "d"},
	}}}}}}
	if n := p.Traces(req); n != 1 {
		t.Fatalf("kept %d spans, want 1", n)
	}
	sp := req.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if sp.Name != "k" || !equalMaps(toMap(sp.Attributes), map[string]string{"a": "b"}) {
		t.Fatalf("unexpected span %+v", sp)
	}
	for _, kv := range sp.Attributes {
		if strings.HasPrefix(kv.Key, "wt.") {
			t.Fatalf("relay emitted %s", kv.Key)
		}
	}
}
