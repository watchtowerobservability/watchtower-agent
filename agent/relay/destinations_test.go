package relay

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

var t0 = time.Date(2026, 11, 9, 13, 5, 0, 0, time.UTC)

func logReq(bodies ...string) *collogs.ExportLogsServiceRequest {
	var recs []*logspb.LogRecord
	for _, b := range bodies {
		recs = append(recs, &logspb.LogRecord{TimeUnixNano: uint64(t0.UnixNano()), SeverityText: "ERROR", Body: strVal(b),
			Attributes: []*commonpb.KeyValue{{Key: "user", Value: strVal("u1")}}})
	}
	return &collogs.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{Key: "service.name", Value: strVal("api")}}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: recs}}}}}
}

func metricReq() *colmetrics.ExportMetricsServiceRequest {
	return &colmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
		Name: "cpu", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{
			{TimeUnixNano: uint64(t0.UnixNano()), Value: &metricspb.NumberDataPoint_AsInt{AsInt: 7}}}}}}}}}}}}
}

func body(t *testing.T, r *http.Request) string {
	t.Helper()
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		g, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		rd = g
	}
	b, _ := io.ReadAll(rd)
	return string(b)
}

// newDest builds a destination around cfg with its queue in a temp dir and delivers whatever
// was offered through step, as the run loop does.
func newDest(t *testing.T, cfg DestConfig, secret string, c *http.Client) *destination {
	t.Helper()
	snd, err := newSender(cfg, c, secret)
	if err != nil {
		t.Fatal(err)
	}
	q, err := OpenQueue(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return &destination{cfg: cfg, snd: snd, q: q, poke: make(chan struct{}, 1)}
}

func offer(d *destination, evs []Event) { d.add(evs) }

func TestEventsOf(t *testing.T) {
	e := EventsOf(logReq("boom"))
	if len(e) != 1 || e[0].Kind != "log" || e[0].Message != "boom" || e[0].Service != "api" || e[0].Attrs["user"] != "u1" || e[0].Attrs["service.name"] != "api" {
		t.Fatalf("%+v", e)
	}
	m := EventsOf(metricReq())
	if len(m) != 1 || *m[0].Value != 7 || m[0].MetricType != "gauge" {
		t.Fatalf("%+v", m)
	}
}

func TestSplunkHEC(t *testing.T) {
	var got, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, auth = body(t, r), r.Header.Get("Authorization")
		if r.URL.Path != "/services/collector/event" {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "s", Type: "splunk_hec", URL: srv.URL, SecretEnv: "X", Index: "main", Sourcetype: "wt"}, "tok", srv.Client())
	offer(d, EventsOf(logReq("a", "b")))
	if err := d.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth != "Splunk tok" || strings.Count(got, "\n") != 2 || !strings.Contains(got, `"index":"main"`) || !strings.Contains(got, `"message":"a"`) {
		t.Fatalf("%q %q", auth, got)
	}
	if d.sent.Load() != 2 || d.q.Depth() != 0 {
		t.Fatal("not acked")
	}
}

func TestRetryKeepsBatchThenDelivers(t *testing.T) {
	var mu sync.Mutex
	calls, fail := 0, true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if fail {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "s", Type: "splunk_hec", URL: srv.URL, SecretEnv: "X"}, "tok", srv.Client())
	offer(d, EventsOf(logReq("a")))
	err := d.step(context.Background())
	var re *retryError
	if err == nil || !asRetry(err, &re) || re.after != 2*time.Second || d.q.Depth() != 1 {
		t.Fatalf("want retryable with batch kept: %v depth %d", err, d.q.Depth())
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if err := d.step(context.Background()); err != nil || d.q.Depth() != 0 || calls != 2 {
		t.Fatalf("%v depth %d calls %d", err, d.q.Depth(), calls)
	}
}

func asRetry(err error, re **retryError) bool {
	r, ok := err.(*retryError) //nolint:errorlint // never wrapped
	*re = r
	return ok
}

func TestPermanentRejectDropsAndCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) }))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "s", Type: "splunk_hec", URL: srv.URL, SecretEnv: "X"}, "tok", srv.Client())
	offer(d, EventsOf(logReq("a")))
	if err := d.step(context.Background()); err != nil || d.rejected.Load() != 1 || d.q.Depth() != 0 {
		t.Fatalf("%v %d", err, d.rejected.Load())
	}
}

func TestElasticsearchBulk(t *testing.T) {
	var got, auth string
	resp := `{"errors":false}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, auth = body(t, r), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(resp))
	}))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "e", Type: "elasticsearch", URL: srv.URL, Index: "wt-%Y.%m.%d"}, "key", srv.Client())
	offer(d, EventsOf(logReq("a")))
	if err := d.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if auth != "ApiKey key" || len(lines) != 2 || !strings.Contains(lines[0], `"_index":"wt-2026.11.09"`) || !strings.Contains(lines[0], `"_id"`) {
		t.Fatalf("%q %q", auth, got)
	}
	resp = `{"errors":true,"items":[{"index":{"status":429}}]}`
	offer(d, EventsOf(logReq("b")))
	if err := d.step(context.Background()); err == nil || d.q.Depth() != 1 {
		t.Fatal("429 item must retry")
	}
	d.cfg.Username = "u"
	d.snd = &esDest{httpDest: httpDest{c: srv.Client(), secret: "p"}, cfg: d.cfg, now: time.Now}
	resp = `{"errors":false}`
	if err := d.step(context.Background()); err != nil || auth != "Basic dTpw" {
		t.Fatalf("%v %q", err, auth)
	}
}

func TestDatadogLogsAndMetrics(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got[r.URL.Path] = body(t, r)
		got["key"] = r.Header.Get("DD-API-KEY")
		w.WriteHeader(202)
	}))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "d", Type: "datadog", URL: srv.URL + "/api/v2/logs", MetricsURL: srv.URL + "/api/v2/series", SecretEnv: "X"}, "k1", srv.Client())
	offer(d, append(EventsOf(logReq("a")), EventsOf(metricReq())...))
	if err := d.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	var logs []map[string]any
	if json.Unmarshal([]byte(got["/api/v2/logs"]), &logs) != nil || len(logs) != 1 || logs[0]["message"] != "a" || logs[0]["status"] != "error" || got["key"] != "k1" {
		t.Fatalf("%v", got)
	}
	var s struct {
		Series []struct {
			Metric string
			Type   int
			Points []struct{ Value float64 }
		}
	}
	if json.Unmarshal([]byte(got["/api/v2/series"]), &s) != nil || len(s.Series) != 1 || s.Series[0].Metric != "cpu" || s.Series[0].Type != 3 || s.Series[0].Points[0].Value != 7 {
		t.Fatalf("%v", got["/api/v2/series"])
	}
}

func TestS3PutSignedPartitioned(t *testing.T) {
	var path, auth, enc, secTok string
	var data []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth, enc = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Encoding")
		secTok = r.Header.Get("X-Amz-Security-Token")
		data, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	t.Setenv("AWS_SESSION_TOKEN", "sess-tok")
	d := newDest(t, DestConfig{Name: "b", Type: "s3", URL: srv.URL, Bucket: "my-bucket", Region: "us-east-1", AccessKey: "AKID", SecretEnv: "X", Prefix: "wt/raw"}, "sek", srv.Client())
	offer(d, EventsOf(logReq("a", "b")))
	if err := d.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, "/my-bucket/wt/raw/logs/dt=2026-11-09/hour=13/") || !strings.HasSuffix(path, ".ndjson.gz") || enc != "gzip" ||
		!strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(auth, "/us-east-1/s3/aws4_request") {
		t.Fatalf("%q %q", path, auth)
	}
	if secTok != "sess-tok" {
		t.Fatalf("session token header %q", secTok)
	}
	g, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(g); strings.Count(string(b), "\n") != 2 {
		t.Fatalf("%q", b)
	}
	first := path
	offer(d, EventsOf(logReq("a", "b")))
	_ = d.step(context.Background())
	if path != first {
		t.Fatal("same content must give the same key, so a retry overwrites")
	}
}

func TestDedupe(t *testing.T) {
	p, err := compileStream(0, StreamProc{Type: "dedupe", Window: time.Minute, Max: 2})
	if err != nil {
		t.Fatal(err)
	}
	ev := func(m string) Event { return Event{Kind: "log", Message: m, Time: t0} }
	now := t0
	out := p.apply([]Event{ev("a"), ev("a"), ev("b")}, now, nil)
	if len(out) != 2 {
		t.Fatalf("%d", len(out))
	}
	// same message at a later timestamp is still a duplicate (full-record hash ignores time)
	later := ev("a")
	later.Time = t0.Add(time.Second)
	if len(p.apply([]Event{later}, now.Add(time.Second), nil)) != 0 {
		t.Fatal("duplicate within window kept")
	}
	if len(p.apply([]Event{ev("a")}, now.Add(2*time.Minute), nil)) != 1 {
		t.Fatal("window expiry must let it through")
	}
	p.apply([]Event{ev("c"), ev("d")}, now.Add(3*time.Minute), nil) // LRU bound 2 evicts a and b
	if len(p.(*dedupe).seen) != 2 {
		t.Fatalf("lru not bounded: %d", len(p.(*dedupe).seen))
	}
	if dr, _ := p.counts(); dr != 2 {
		t.Fatalf("dropped %d", dr)
	}
	f, _ := compileStream(0, StreamProc{Type: "dedupe", Fields: []string{"message", "user"}})
	a, b := ev("x"), ev("x")
	a.Attrs, b.Attrs = map[string]string{"user": "1"}, map[string]string{"user": "2"}
	if len(f.apply([]Event{a, b, a}, now, nil)) != 2 {
		t.Fatal("field-set dedupe")
	}
}

func TestQuotaDropAndOverflow(t *testing.T) {
	ev := func(s string) Event { return Event{Kind: "log", Service: s, Message: "m", Time: t0} }
	p, _ := compileStream(0, StreamProc{Type: "quota", Key: "service", MaxEvents: 2, Window: time.Minute})
	out := p.apply([]Event{ev("a"), ev("a"), ev("a"), ev("b")}, t0, nil)
	if len(out) != 3 {
		t.Fatalf("per-key budget: %d", len(out))
	}
	if len(p.apply([]Event{ev("a")}, t0.Add(time.Minute), nil)) != 1 {
		t.Fatal("budget must reset with the window")
	}
	if dr, ov := p.counts(); dr != 1 || ov != 0 {
		t.Fatalf("%d %d", dr, ov)
	}
	o, _ := compileStream(0, StreamProc{Type: "quota", MaxBytes: 200, Overflow: "cold"})
	over := map[string][]Event{}
	kept := o.apply([]Event{ev("a"), ev("a"), ev("a"), ev("a")}, t0, over)
	if len(kept) == 0 || len(kept) == 4 || len(kept)+len(over["cold"]) != 4 {
		t.Fatalf("bytes quota kept %d overflow %d", len(kept), len(over["cold"]))
	}
	if _, ov := o.counts(); ov != int64(len(over["cold"])) {
		t.Fatal("overflow counter")
	}
}

func TestDestsFanOutAndOverflowOnly(t *testing.T) {
	mk := func(name string, only bool) *destination {
		return newDest(t, DestConfig{Name: name, Type: "splunk_hec", URL: "http://127.0.0.1:1", SecretEnv: "X", OverflowOnly: only}, "t", nil)
	}
	main, cold := mk("main", false), mk("cold", true)
	q, _ := compileStream(0, StreamProc{Type: "quota", MaxEvents: 1, Overflow: "cold"})
	ds := &Dests{procs: []streamProc{q}, dests: []*destination{main, cold}, by: map[string]*destination{"main": main, "cold": cold}}
	ds.Offer(logReq("a", "b"))
	if main.q.Depth() != 1 || cold.q.Depth() != 1 || main.n != 1 || cold.n != 1 {
		t.Fatalf("main %d cold %d", main.q.Depth(), cold.q.Depth())
	}
	var sb strings.Builder
	ds.WriteMetrics(&sb)
	if !strings.Contains(sb.String(), `wt_relay_proc_overflow_events_total{proc="quota0"} 1`) {
		t.Fatal(sb.String())
	}
}

func TestDestConfigValidation(t *testing.T) {
	base := func() Config {
		var c Config
		c.Upstream, c.Queue.Dir = "https://ingest.example.com", "/tmp/q"
		return c
	}
	bad := map[string]func(*Config){
		"unknown type": func(c *Config) { c.Destinations = []DestConfig{{Name: "x", Type: "kafka"}} },
		"dup name": func(c *Config) {
			c.Destinations = []DestConfig{{Name: "x", Type: "elasticsearch", URL: "https://e"}, {Name: "x", Type: "elasticsearch", URL: "https://e"}}
		},
		"s3 no bucket": func(c *Config) {
			c.Destinations = []DestConfig{{Name: "x", Type: "s3", Region: "r", AccessKey: "a", SecretEnv: "S"}}
		},
		"splunk no tok": func(c *Config) { c.Destinations = []DestConfig{{Name: "x", Type: "splunk_hec", URL: "https://s"}} },
		"plain http": func(c *Config) {
			c.Destinations = []DestConfig{{Name: "x", Type: "elasticsearch", URL: "http://es.example.com"}}
		},
		"bad overflow":   func(c *Config) { c.StreamProcessors = []StreamProc{{Type: "quota", MaxEvents: 1, Overflow: "nope"}} },
		"quota no limit": func(c *Config) { c.StreamProcessors = []StreamProc{{Type: "quota"}} },
		"bad proc":       func(c *Config) { c.StreamProcessors = []StreamProc{{Type: "x"}} },
	}
	for name, f := range bad {
		c := base()
		f(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base()
	c.Destinations = []DestConfig{{Name: "dd", Type: "datadog", Site: "datadoghq.eu", SecretEnv: "K"}, {Name: "cold", Type: "elasticsearch", URL: "https://es.example.com"}}
	c.StreamProcessors = []StreamProc{{Type: "dedupe"}, {Type: "quota", MaxEvents: 5, Overflow: "cold"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestS3CredentialsFromEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	snd, err := newSender(DestConfig{Name: "b", Type: "s3", Bucket: "my-bucket", Region: "eu-west-1"}, http.DefaultClient, "envsecret")
	if err != nil || snd.(*s3Dest).cfg.AccessKey != "ENVKEY" {
		t.Fatalf("%v", err)
	}
	if _, err := newSender(DestConfig{Name: "b", Type: "s3", Bucket: "my-bucket", Region: "eu-west-1"}, http.DefaultClient, ""); err == nil {
		t.Fatal("missing secret accepted")
	}
}

// Events are on disk when add returns: reopening the queue after an unflushed close finds them.
func TestOfferIsDurable(t *testing.T) {
	dir := t.TempDir()
	q, err := OpenQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	snd, _ := newSender(DestConfig{Name: "s", Type: "splunk_hec", URL: "http://127.0.0.1:1", SecretEnv: "X"}, nil, "")
	d := &destination{cfg: DestConfig{Name: "s"}, snd: snd, q: q, poke: make(chan struct{}, 1)}
	d.add(EventsOf(logReq("a", "b")))
	q.Close() // no drain, no flush: the process "crashes" here
	q2, err := OpenQueue(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	var got []Event
	_ = q2.Drain(func(_ string, b []byte) error {
		var raw []Event
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		got = append(got, raw...)
		return nil
	})
	if len(got) != 2 || got[0].Message != "a" || got[1].Message != "b" {
		t.Fatalf("%+v", got)
	}
}

func TestBatchesAcrossRecords(t *testing.T) {
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, body(t, r))
		mu.Unlock()
	}))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "s", Type: "splunk_hec", URL: srv.URL, SecretEnv: "X"}, "tok", srv.Client())
	for _, m := range []string{"a", "b", "c"} {
		d.add(EventsOf(logReq(m)))
	}
	if d.due() {
		t.Fatal("3 events under max_events and max_age must wait")
	}
	if err := d.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || strings.Count(reqs[0], "\n") != 3 || d.q.Depth() != 0 {
		t.Fatalf("want one request of 3 events, got %d", len(reqs))
	}
	d.cfg.Batch.MaxEvents = 2
	reqs = nil
	for _, m := range []string{"a", "b", "c"} {
		d.add(EventsOf(logReq(m)))
	}
	if err := d.step(context.Background()); err != nil || len(reqs) != 2 {
		t.Fatalf("max_events 2 over 3 events: %v, %d requests", err, len(reqs))
	}
}

func TestDatadogTraces(t *testing.T) {
	var got []byte
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("DD-API-KEY")
		got = []byte(body(t, r))
	}))
	defer srv.Close()
	d := newDest(t, DestConfig{Name: "d", Type: "datadog", TracesURL: srv.URL + "/api/v0.2/traces", SecretEnv: "X", Hostname: "h1"}, "k1", srv.Client())
	sp := Event{Kind: "span", Time: t0, Name: "GET /x", Service: "api", TraceID: "0102030405060708" + "00000000000000ff", SpanID: "00000000000000aa",
		ParentID: "00000000000000bb", DurationNs: 1500, Error: true, Message: "boom", Attrs: map[string]string{"http.method": "GET"}}
	offer(d, []Event{sp})
	if err := d.step(context.Background()); err != nil || key != "k1" {
		t.Fatalf("%v %q", err, key)
	}
	// walk AgentPayload{5: TracerPayload{6: TraceChunk{3: Span}}} with protowire
	field := func(b []byte, want protowire.Number) []byte {
		for len(b) > 0 {
			n, typ, l := protowire.ConsumeTag(b)
			b = b[l:]
			if typ == protowire.BytesType {
				v, l := protowire.ConsumeBytes(b)
				if n == want {
					return v
				}
				b = b[l:]
			} else {
				l := protowire.ConsumeFieldValue(n, typ, b)
				b = b[l:]
			}
		}
		return nil
	}
	span := field(field(field(got, 5), 6), 3)
	if string(field(span, 1)) != "api" || string(field(span, 2)) != "GET /x" || !bytes.Contains(span, []byte("_dd.p.tid")) || !bytes.Contains(span, []byte("error.msg")) {
		t.Fatalf("span %q", span)
	}
	if hexU64(sp.TraceID) != 0xff || hexU64(sp.SpanID) != 0xaa {
		t.Fatal("id split")
	}
}
