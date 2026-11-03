package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func str(s string) *common.AnyValue {
	return &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: s}}
}

func logBatch(t *testing.T) []byte {
	t.Helper()
	b, err := proto.Marshal(&collectorlogs.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resource.Resource{Attributes: []*common.KeyValue{{Key: "service.name", Value: str("api")}}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{TimeUnixNano: 1_700_000_000_000_000_000, SeverityText: "WARN", Body: str("disk full"),
			Attributes: []*common.KeyValue{{Key: "a", Value: str("b")}}}}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSplunkHECSink(t *testing.T) {
	var got, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, auth = string(b), r.Header.Get("Authorization")
	}))
	defer srv.Close()
	f, err := newForwarder(context.Background(), ForwardTarget{Kind: "splunkhec", Endpoint: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	f.hc = srv.Client()
	if err := f.send(context.Background(), fwdItem{"logs", logBatch(t)}); err != nil {
		t.Fatal(err)
	}
	if auth != "Splunk tok" || !strings.Contains(got, `"event":"disk full"`) || !strings.Contains(got, `"source":"api"`) {
		t.Fatalf("%s %s", auth, got)
	}
	got = ""
	if err := f.send(context.Background(), fwdItem{"traces", []byte{}}); err != nil || got != "" {
		t.Fatalf("traces must be skipped: %v %q", err, got)
	}
}

func TestOAuth2AuthIsCachedOnOTLP(t *testing.T) {
	var tokens atomic.Int64
	var seen atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokens.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "s" {
				w.WriteHeader(401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "expires_in": 3600})
			return
		}
		seen.Store(r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	f, err := newForwarder(context.Background(), ForwardTarget{Kind: "otlp_http", Endpoint: srv.URL, OAuth2: &ForwardOAuth2{TokenURL: srv.URL + "/token", ClientID: "c", ClientSecret: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	f.hc = srv.Client()
	for range 2 {
		if err := f.send(context.Background(), fwdItem{"logs", []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	if tokens.Load() != 1 || seen.Load() != "Bearer at" {
		t.Fatalf("tokens=%d auth=%v", tokens.Load(), seen.Load())
	}
}

func TestSplitByTraceKeepsATraceTogether(t *testing.T) {
	span := func(id byte) *tracepb.Span { return &tracepb.Span{TraceId: []byte{id}, SpanId: []byte{id}} }
	b, _ := proto.Marshal(&collectortrace.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{ScopeSpans: []*tracepb.ScopeSpans{{
		Spans: []*tracepb.Span{span(1), span(2), span(1), span(3), span(2)}}}}}})
	parts, err := splitByTrace(b, 2)
	if err != nil {
		t.Fatal(err)
	}
	where := map[byte]int{}
	total := 0
	for i, p := range parts {
		var r collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(p, &r); err != nil {
			t.Fatal(err)
		}
		for _, rs := range r.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				for _, s := range ss.GetSpans() {
					total++
					if at, ok := where[s.GetTraceId()[0]]; ok && at != i {
						t.Fatalf("trace %d on two endpoints", s.GetTraceId()[0])
					}
					where[s.GetTraceId()[0]] = i
				}
			}
		}
	}
	if total != 5 {
		t.Fatalf("got %d spans", total)
	}
}

func TestSyslogFrame(t *testing.T) {
	lines, err := logLines(logBatch(t))
	if err != nil {
		t.Fatal(err)
	}
	s := formatSyslog(lines[0])
	if !strings.Contains(s, "<132>1 2023-11-14T22:13:20Z - api - - - disk full") {
		t.Fatal(s)
	}
}
