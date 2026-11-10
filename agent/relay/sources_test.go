package relay

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/internal/srcconv"
)

type queued struct {
	path string
	body []byte
}

func srcRelay(t *testing.T) *Relay {
	t.Helper()
	proc, err := Compile(ProcessorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	mproc, err := CompileMetrics(nil)
	if err != nil {
		t.Fatal(err)
	}
	q, err := OpenQueue(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return &Relay{Proc: proc, MProc: mproc, Q: q, poke: make(chan struct{}, 1)}
}

// drained returns (and leaves queued) what the relay has queued so far.
func drained(t *testing.T, r *Relay) []queued {
	t.Helper()
	var out []queued
	_ = r.Q.Drain(func(p string, b []byte) error {
		out = append(out, queued{p, append([]byte(nil), b...)})
		return errStop
	})
	return out
}

var errStop = context.Canceled

// takeAll drains everything (consuming it).
func takeAll(t *testing.T, r *Relay) []queued {
	t.Helper()
	var out []queued
	if err := r.Q.Drain(func(p string, b []byte) error {
		out = append(out, queued{p, append([]byte(nil), b...)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func logsOf(t *testing.T, q queued) *collogs.ExportLogsServiceRequest {
	t.Helper()
	if q.path != "/v1/logs" {
		t.Fatalf("queued %s, want /v1/logs", q.path)
	}
	req := &collogs.ExportLogsServiceRequest{}
	if err := proto.Unmarshal(q.body, req); err != nil {
		t.Fatal(err)
	}
	return req
}

func post(t *testing.T, url, ct string, hdr map[string]string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestDatadogSourceLogsAndAuth(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.datadogHandler("k1"))
	defer srv.Close()
	body := `[{"message":"boom","service":"shop","hostname":"h1","ddtags":"env:prod","status":"error","extra":{"a":1}}]`
	if resp := post(t, srv.URL+"/api/v2/logs", "application/json", map[string]string{"DD-API-KEY": "bad"}, []byte(body)); resp.StatusCode != 403 {
		t.Fatalf("bad key: %d", resp.StatusCode)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(body))
	_ = w.Close()
	resp := post(t, srv.URL+"/api/v2/logs", "application/json", map[string]string{"DD-API-KEY": "k1", "Content-Encoding": "gzip"}, gz.Bytes())
	if resp.StatusCode != 202 {
		t.Fatalf("logs: %d", resp.StatusCode)
	}
	items := takeAll(t, r)
	if len(items) != 1 {
		t.Fatalf("queued %d", len(items))
	}
	req := logsOf(t, items[0])
	rec := req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if rec.Body.GetStringValue() != "boom" || rec.SeverityText != "error" || req.ResourceLogs[0].Resource.Attributes[0].Value.GetStringValue() != "shop" {
		t.Fatalf("%v", req)
	}
	attrs := toMap(rec.Attributes)
	if attrs["host.name"] != "h1" || attrs["env"] != "prod" || attrs["extra.a"] != "1" {
		t.Fatalf("%v", attrs)
	}
}

func TestDatadogSourceSeriesAndValidate(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.datadogHandler(""))
	defer srv.Close()
	body := `{"series":[{"metric":"app.hits","type":"count","points":[[1700000000,3]],"tags":["env:p"]}]}`
	if resp := post(t, srv.URL+"/api/v1/series", "application/json", nil, []byte(body)); resp.StatusCode != 202 {
		t.Fatalf("series: %d", resp.StatusCode)
	}
	items := takeAll(t, r)
	if len(items) != 1 || items[0].path != "/v1/metrics" {
		t.Fatalf("%v", items)
	}
	req := &colmetrics.ExportMetricsServiceRequest{}
	if err := proto.Unmarshal(items[0].body, req); err != nil {
		t.Fatal(err)
	}
	m := req.ResourceMetrics[0].ScopeMetrics[0].Metrics[0]
	if m.Name != "app.hits" || m.GetSum().DataPoints[0].GetAsDouble() != 3 {
		t.Fatalf("%v", m)
	}
	if resp := post(t, srv.URL+"/api/v2/series", "application/json", nil, []byte("{")); resp.StatusCode != 400 {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
	resp, err := http.Get(srv.URL + "/api/v1/validate")
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err, resp)
	}
	_ = resp.Body.Close()
}

// msgpack encoders for the tests (short strings and small ints only).
func mpS(s string) []byte { return append([]byte{0xa0 | byte(len(s))}, s...) }
func mpA(items ...[]byte) []byte {
	return append([]byte{0x90 | byte(len(items))}, bytes.Join(items, nil)...)
}
func mpM(kv ...[]byte) []byte {
	return append([]byte{0x80 | byte(len(kv)/2)}, bytes.Join(kv, nil)...)
}
func mpU(n byte) []byte { return []byte{n} }

func TestDatadogSourceTraces(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.datadogHandler(""))
	defer srv.Close()
	span := mpM(mpS("trace_id"), mpU(5), mpS("span_id"), mpU(6), mpS("parent_id"), mpU(0), mpS("name"), mpS("web.request"),
		mpS("service"), mpS("shop"), mpS("start"), mpU(1), mpS("duration"), mpU(2))
	resp := post(t, srv.URL+"/v0.4/traces", "application/msgpack", nil, mpA(mpA(span)))
	if resp.StatusCode != 200 {
		t.Fatalf("traces: %d", resp.StatusCode)
	}
	items := takeAll(t, r)
	if len(items) != 1 || items[0].path != "/v1/traces" {
		t.Fatalf("%v", items)
	}
	req := &coltrace.ExportTraceServiceRequest{}
	if err := proto.Unmarshal(items[0].body, req); err != nil {
		t.Fatal(err)
	}
	if sp := req.ResourceSpans[0].ScopeSpans[0].Spans[0]; sp.Name != "web.request" || len(sp.TraceId) != 16 {
		t.Fatalf("%v", sp)
	}
	if resp := post(t, srv.URL+"/v0.4/traces", "application/msgpack", nil, []byte{0xc1}); resp.StatusCode != 400 {
		t.Fatalf("garbage: %d", resp.StatusCode)
	}
}

func TestHECSource(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.hecHandler("sp-tok"))
	defer srv.Close()
	ev := `{"time":1700000000,"host":"h","sourcetype":"app","event":"hello"}{"event":"metric","fields":{"metric_name":"cpu","_value":2,"dc":"x"}}`
	if resp := post(t, srv.URL+"/services/collector/event", "application/json", map[string]string{"Authorization": "Splunk nope"}, []byte(ev)); resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	hdr := map[string]string{"Authorization": "Splunk sp-tok"}
	if resp := post(t, srv.URL+"/services/collector/event", "application/json", hdr, []byte(ev)); resp.StatusCode != 200 {
		t.Fatalf("event: %d", resp.StatusCode)
	}
	items := takeAll(t, r)
	if len(items) != 2 || items[0].path != "/v1/logs" || items[1].path != "/v1/metrics" {
		t.Fatalf("%v", items)
	}
	rec := logsOf(t, items[0]).ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if rec.Body.GetStringValue() != "hello" || toMap(rec.Attributes)["splunk.sourcetype"] != "app" {
		t.Fatalf("%v", rec)
	}
	if resp := post(t, srv.URL+"/services/collector/raw?host=hh&source=s&channel=00000000-0000-0000-0000-000000000001", "text/plain", hdr, []byte("a\nb\n")); resp.StatusCode != 200 {
		t.Fatalf("raw: %d", resp.StatusCode)
	}
	items = takeAll(t, r)
	recs := logsOf(t, items[0]).ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(recs) != 2 || toMap(recs[0].Attributes)["host.name"] != "hh" {
		t.Fatalf("%v", recs)
	}
	if resp := post(t, srv.URL+"/services/collector/event", "application/json", hdr, []byte("not json")); resp.StatusCode != 400 {
		t.Fatalf("bad body: %d", resp.StatusCode)
	}
}

func fluentExchange(t *testing.T, r *Relay, msg []byte) []byte {
	t.Helper()
	srvC, cliC := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.fluentConn(ctx, srvC, ""); close(done) }()
	defer func() { cancel(); _ = cliC.Close(); <-done }()
	_ = cliC.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := cliC.Write(msg); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 32)
	n, err := cliC.Read(ack)
	if err != nil {
		t.Fatal(err)
	}
	return ack[:n]
}

func TestFluentForwardModes(t *testing.T) {
	r := srcRelay(t)
	opt := mpM(mpS("chunk"), mpS("abc"))
	// Message: [tag, time, record, option]
	ack := fluentExchange(t, r, mpA(mpS("app.web"), mpU(10), mpM(mpS("log"), mpS("one"), mpS("level"), mpS("warn")), opt))
	if !bytes.Equal(ack, []byte{0x81, 0xa3, 'a', 'c', 'k', 0xa3, 'a', 'b', 'c'}) {
		t.Fatalf("ack %x", ack)
	}
	// Forward: [tag, [[time, record], ...], option]
	fluentExchange(t, r, mpA(mpS("app.web"), mpA(mpA(mpU(1), mpM(mpS("message"), mpS("two"))), mpA(mpU(2), mpM(mpS("message"), mpS("three")))), opt))
	// PackedForward: bin of concatenated [time, record]
	packed := append(mpA(mpU(1), mpM(mpS("log"), mpS("four"))), mpA(mpU(2), mpM(mpS("log"), mpS("five")))...)
	bin := append([]byte{0xc4, byte(len(packed))}, packed...)
	fluentExchange(t, r, mpA(mpS("app.web"), bin, opt))
	var bodies []string
	for _, it := range takeAll(t, r) {
		for _, rec := range logsOf(t, it).ResourceLogs[0].ScopeLogs[0].LogRecords {
			bodies = append(bodies, rec.Body.GetStringValue())
			if toMap(rec.Attributes)["fluent.tag"] != "app.web" {
				t.Fatalf("tag: %v", rec.Attributes)
			}
		}
	}
	if strings.Join(bodies, ",") != "one,two,three,four,five" {
		t.Fatalf("%v", bodies)
	}
}

func TestSyslogSourceUDP(t *testing.T) {
	r := srcRelay(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback udp")
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.startSyslog(ctx, SourceConfig{Type: SrcSyslog, UDP: addr}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = c.Write([]byte("<34>1 2024-01-02T03:04:05Z host1 su 77 ID47 [ex@1 a=\"b\"] denied"))
		time.Sleep(200 * time.Millisecond)
		if items := drained(t, r); len(items) > 0 {
			rec := logsOf(t, items[0]).ResourceLogs[0].ScopeLogs[0].LogRecords[0]
			a := toMap(rec.Attributes)
			if rec.Body.GetStringValue() != "denied" || a["syslog.hostname"] != "host1" || a["syslog.app"] != "su" || a["sd.ex@1.a"] != "b" {
				t.Fatalf("%v %v", rec, a)
			}
			return
		}
	}
	t.Fatal("no syslog record queued")
}

func TestSourceConfigValidation(t *testing.T) {
	ok := []SourceConfig{
		{Type: SrcDatadog, Listen: ":8126", TokenFile: "k", CertFile: "c", KeyFile: "k"},
		{Type: SrcHEC, Listen: ":8088", AllowUnauthenticated: true},
		{Type: SrcSyslog, UDP: ":5514", TCP: ":5514", AllowUnauthenticated: true},
		{Type: SrcFluent, Listen: ":24224", SharedKeyFile: "sk"},
		{Type: SrcKafka, Brokers: []string{"k:9092"}, Topics: []string{"logs"}},
	}
	if err := validateSources(ok, ":4318", ":4317"); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]SourceConfig{
		"unknown type":    {{Type: "nats"}},
		"no listen":       {{Type: SrcHEC}},
		"dup listen":      {{Type: SrcHEC, Listen: ":8088"}, {Type: SrcDatadog, Listen: ":8088"}},
		"otlp clash":      {{Type: SrcHEC, Listen: ":4318"}},
		"syslog empty":    {{Type: SrcSyslog}},
		"kafka no topic":  {{Type: SrcKafka, Brokers: []string{"k:1"}}},
		"token on fluent": {{Type: SrcFluent, Listen: ":1", TokenFile: "x"}},
		"half sasl":       {{Type: SrcKafka, Brokers: []string{"k:1"}, Topics: []string{"t"}, SASLUsername: "u"}},
		"bad addr":        {{Type: SrcFluent, Listen: "nope"}},
	} {
		if validateSources(bad, ":4318", ":4317") == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDatadogSourceEventsStatsAndSketches(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.datadogHandler(""))
	defer srv.Close()
	ev := `{"title":"deploy","text":"v2","host":"h","alert_type":"warning","tags":["env:p"]}`
	if resp := post(t, srv.URL+"/api/v1/events", "application/json", nil, []byte(ev)); resp.StatusCode != 202 {
		t.Fatalf("events: %d", resp.StatusCode)
	}
	rec := logsOf(t, takeAll(t, r)[0]).ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if a := toMap(rec.Attributes); a["datadog.event"] != "true" || a["env"] != "p" || rec.SeverityText != "warn" {
		t.Fatalf("%v", rec)
	}
	group := mpM(mpS("Service"), mpS("shop"), mpS("Hits"), mpU(3))
	bucket := mpM(mpS("Start"), mpU(1), mpS("Duration"), mpU(2), mpS("Stats"), mpA(group))
	stats := mpM(mpS("AgentHostname"), mpS("a1"), mpS("Stats"), mpA(mpM(mpS("Hostname"), mpS("h1"), mpS("Stats"), mpA(bucket))))
	if resp := post(t, srv.URL+"/api/v0.2/stats", "application/msgpack", nil, stats); resp.StatusCode != 202 {
		t.Fatalf("stats: %d", resp.StatusCode)
	}
	items := takeAll(t, r)
	if len(items) != 1 || items[0].path != "/v1/metrics" {
		t.Fatalf("%v", items)
	}
	// a sketch payload: one sketch "lat" with one dogsketch (ts 5, count 1, key 100 count 1)
	var ds []byte
	ds = protowire.AppendTag(ds, 1, protowire.VarintType)
	ds = protowire.AppendVarint(ds, 5)
	ds = protowire.AppendTag(ds, 7, protowire.BytesType)
	ds = protowire.AppendBytes(ds, protowire.AppendVarint(nil, protowire.EncodeZigZag(100)))
	ds = protowire.AppendTag(ds, 8, protowire.BytesType)
	ds = protowire.AppendBytes(ds, protowire.AppendVarint(nil, 1))
	var sk []byte
	sk = protowire.AppendTag(sk, 1, protowire.BytesType)
	sk = protowire.AppendString(sk, "lat")
	sk = protowire.AppendTag(sk, 7, protowire.BytesType)
	sk = protowire.AppendBytes(sk, ds)
	var payload []byte
	payload = protowire.AppendTag(payload, 1, protowire.BytesType)
	payload = protowire.AppendBytes(payload, sk)
	if resp := post(t, srv.URL+"/api/beta/sketches", "application/x-protobuf", nil, payload); resp.StatusCode != 202 {
		t.Fatalf("sketches: %d", resp.StatusCode)
	}
	items = takeAll(t, r)
	req := &colmetrics.ExportMetricsServiceRequest{}
	if len(items) != 1 || proto.Unmarshal(items[0].body, req) != nil || req.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Name != "lat" {
		t.Fatalf("%v", items)
	}
}

func TestDatadogSourceTracesV02Proto(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.datadogHandler(""))
	defer srv.Close()
	var span []byte
	span = protowire.AppendTag(span, 1, protowire.BytesType)
	span = protowire.AppendString(span, "shop")
	span = protowire.AppendTag(span, 2, protowire.BytesType)
	span = protowire.AppendString(span, "web.request")
	for num, v := range map[protowire.Number]uint64{4: 5, 5: 6, 7: 1, 8: 2} {
		span = protowire.AppendTag(span, num, protowire.VarintType)
		span = protowire.AppendVarint(span, v)
	}
	var chunk, tp, agent []byte
	chunk = protowire.AppendTag(chunk, 3, protowire.BytesType)
	chunk = protowire.AppendBytes(chunk, span)
	tp = protowire.AppendTag(tp, 6, protowire.BytesType)
	tp = protowire.AppendBytes(tp, chunk)
	tp = protowire.AppendTag(tp, 8, protowire.BytesType)
	tp = protowire.AppendString(tp, "prod")
	agent = protowire.AppendTag(agent, 5, protowire.BytesType)
	agent = protowire.AppendBytes(agent, tp)
	if resp := post(t, srv.URL+"/api/v0.2/traces", "application/x-protobuf", nil, agent); resp.StatusCode != 202 {
		t.Fatalf("v0.2: %d", resp.StatusCode)
	}
	items := takeAll(t, r)
	req := &coltrace.ExportTraceServiceRequest{}
	if len(items) != 1 || proto.Unmarshal(items[0].body, req) != nil {
		t.Fatalf("%v", items)
	}
	rs := req.ResourceSpans[0]
	if rs.ScopeSpans[0].Spans[0].Name != "web.request" || toMap(rs.Resource.Attributes)["deployment.environment"] != "prod" {
		t.Fatalf("%v", rs)
	}
}

func TestHECAckAndChannels(t *testing.T) {
	r := srcRelay(t)
	srv := httptest.NewServer(r.hecHandler(""))
	defer srv.Close()
	hdr := map[string]string{"X-Splunk-Request-Channel": "chan-1"}
	for want := range 2 {
		resp := post(t, srv.URL+"/services/collector/event", "application/json", hdr, []byte(`{"event":"x"}`))
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"ackId":`+strconv.Itoa(want)) {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	}
	// no channel: no ackId; raw without a channel is refused
	resp := post(t, srv.URL+"/services/collector/event", "application/json", nil, []byte(`{"event":"x"}`))
	if b, _ := io.ReadAll(resp.Body); strings.Contains(string(b), "ackId") {
		t.Fatalf("%s", b)
	}
	if resp := post(t, srv.URL+"/services/collector/raw", "text/plain", nil, []byte("a")); resp.StatusCode != 400 {
		t.Fatalf("raw without channel: %d", resp.StatusCode)
	}
	resp = post(t, srv.URL+"/services/collector/ack?channel=chan-1", "application/json", nil, []byte(`{"acks":[0,1,7]}`))
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != `{"acks":{"0":true,"1":true,"7":false}}` {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp = post(t, srv.URL+"/services/collector/ack", "application/json", hdr, []byte(`{"acks":[0]}`))
	if b, _ := io.ReadAll(resp.Body); string(b) != `{"acks":{"0":false}}` {
		t.Fatalf("an acked id is reported once: %s", b)
	}
	// another channel never sees chan-1's ids
	resp = post(t, srv.URL+"/services/collector/ack", "application/json", map[string]string{"X-Splunk-Request-Channel": "other"}, []byte(`{"acks":[1]}`))
	if b, _ := io.ReadAll(resp.Body); string(b) != `{"acks":{"1":false}}` {
		t.Fatalf("%s", b)
	}
}

func TestFluentSharedKeyHandshake(t *testing.T) {
	for _, tc := range []struct {
		name, clientKey string
		ok              bool
	}{{"good key", "sekret", true}, {"wrong key", "nope", false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := srcRelay(t)
			srvC, cliC := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { r.fluentConn(ctx, srvC, "sekret"); close(done) }()
			defer func() { cancel(); _ = cliC.Close(); <-done }()
			_ = cliC.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 512)
			n, err := cliC.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			helo, _, err := srcconv.MsgpackNext(buf[:n], false)
			arr, _ := helo.([]any)
			if err != nil || len(arr) != 2 || arr[0] != "HELO" {
				t.Fatalf("%v %v", helo, err)
			}
			nonce := []byte(srcconv.MPStr(arr[1].(map[string]any)["nonce"]))
			salt, host := []byte("salty"), []byte("cli")
			ping := append([]byte{0x96}, mpStr("PING")...)
			ping = append(ping, mpStr("cli")...)
			ping = append(ping, mpStr("salty")...)
			ping = append(ping, mpStr(sha512Hex(salt, host, nonce, []byte(tc.clientKey)))...)
			ping = append(ping, mpStr("")...)
			ping = append(ping, mpStr("")...)
			if _, err := cliC.Write(ping); err != nil {
				t.Fatal(err)
			}
			n, err = cliC.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			pong, _, _ := srcconv.MsgpackNext(buf[:n], false)
			pa, _ := pong.([]any)
			if len(pa) != 5 || pa[0] != "PONG" || pa[1] != tc.ok {
				t.Fatalf("pong %v", pong)
			}
			if !tc.ok {
				if _, err := cliC.Read(buf); err == nil {
					t.Fatal("connection stayed open after a failed handshake")
				}
				return
			}
			srvHost, _ := os.Hostname()
			if pa[4] != sha512Hex(salt, []byte(srvHost), nonce, []byte("sekret")) {
				t.Fatal("server digest wrong")
			}
			msg := mpA(mpS("t"), mpU(1), mpM(mpS("log"), mpS("authed")), mpM(mpS("chunk"), mpS("c1")))
			if _, err := cliC.Write(msg); err != nil {
				t.Fatal(err)
			}
			if n, err = cliC.Read(buf); err != nil || n != 8 {
				t.Fatalf("ack: %d %v", n, err)
			}
			if items := takeAll(t, r); len(items) != 1 {
				t.Fatalf("%d batches", len(items))
			}
		})
	}
}
