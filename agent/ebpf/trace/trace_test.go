package trace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"
)

var t0 = time.Unix(1_700_000_000, 0)

func ev(dir Dir, data string) Event {
	return Event{TS: t0, PID: 7, FD: 9, Dir: dir, Data: []byte(data), PeerAddr: "10.0.0.5", PeerPort: 8080}
}

// pair feeds a request on a client socket and its response and returns the finished span.
func pair(t *testing.T, req, resp string) Span {
	t.Helper()
	a := NewAssembler()
	if _, ok := a.Handle(ev(Send, req)); ok {
		t.Fatal("request must not finish a span")
	}
	r := ev(Recv, resp)
	r.TS = t0.Add(5 * time.Millisecond)
	sp, ok := a.Handle(r)
	if !ok {
		t.Fatal("response did not finish a span")
	}
	return sp
}

func TestHTTP1RequestParse(t *testing.T) {
	m, ok := ParseHTTP1([]byte("POST /v1/orders HTTP/1.1\r\nHost: shop.internal:8080\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"))
	if !ok || !m.Request || m.Method != "POST" || m.Path != "/v1/orders" || m.Authority != "shop.internal:8080" {
		t.Fatalf("got %+v ok=%v", m, ok)
	}
	r, ok := ParseHTTP1([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
	if !ok || r.Request || r.Status != 503 {
		t.Fatalf("got %+v", r)
	}
	if _, ok := ParseHTTP1([]byte("\x16\x03\x01 not http")); ok {
		t.Fatal("TLS bytes parsed as HTTP")
	}
}

func h2Frame(typ, flags byte, stream uint32, payload []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags})
	_ = binary.Write(&b, binary.BigEndian, stream)
	b.Write(payload)
	return b.Bytes()
}

func hpackBlock(enc *hpack.Encoder, buf *bytes.Buffer, fields ...[2]string) []byte {
	buf.Reset()
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	return append([]byte(nil), buf.Bytes()...)
}

func TestHTTP2HpackHeadersParse(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	req := hpackBlock(enc, &buf, [2]string{":method", "POST"}, [2]string{":scheme", "http"},
		[2]string{":path", "/pkg.Greeter/SayHello?x=1"}, [2]string{":authority", "greeter:50051"},
		[2]string{"content-type", "application/grpc"}, [2]string{"authorization", "Bearer SECRET"})
	c := &H2Conn{}
	ms := c.Feed(append([]byte(h2Preface), h2Frame(1, 0x4, 1, req)...))
	if len(ms) != 1 || !ms[0].Request || ms[0].Method != "POST" || ms[0].Path != "/pkg.Greeter/SayHello" || !ms[0].IsGRPC() {
		t.Fatalf("got %+v", ms)
	}
	// A second block on the same connection uses the dynamic table built by the first.
	req2 := hpackBlock(enc, &buf, [2]string{":method", "POST"}, [2]string{":path", "/pkg.Greeter/SayBye"},
		[2]string{"content-type", "application/grpc"})
	ms = c.Feed(h2Frame(1, 0x4, 3, req2))
	if len(ms) != 1 || ms[0].Path != "/pkg.Greeter/SayBye" || ms[0].Stream != 3 || !ms[0].IsGRPC() {
		t.Fatalf("second block: %+v", ms)
	}
}

func TestGrpcMethodFromPath(t *testing.T) {
	s, m, ok := GrpcMethod("/pkg.Greeter/SayHello")
	if !ok || s != "pkg.Greeter" || m != "SayHello" {
		t.Fatalf("got %q %q %v", s, m, ok)
	}
	for _, bad := range []string{"/", "/svc", "/a/b/c", ""} {
		if _, _, ok := GrpcMethod(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestGrpcSpanFromHTTP2(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	reqEnc := hpackBlock(enc, &buf, [2]string{":method", "POST"}, [2]string{":path", "/pkg.Greeter/SayHello"},
		[2]string{":authority", "greeter"}, [2]string{"content-type", "application/grpc"})
	var buf2 bytes.Buffer
	enc2 := hpack.NewEncoder(&buf2)
	resp := hpackBlock(enc2, &buf2, [2]string{":status", "200"}, [2]string{"content-type", "application/grpc"}, [2]string{"grpc-status", "0"})
	a := NewAssembler()
	a.Handle(ev(Send, h2Preface+string(h2Frame(1, 0x4, 1, reqEnc))))
	sp, ok := a.Handle(ev(Recv, string(h2Frame(1, 0x5, 1, resp))))
	if !ok || sp.Attrs["rpc.system"] != "grpc" || sp.Attrs["rpc.method"] != "SayHello" || sp.Error {
		t.Fatalf("got %+v ok=%v", sp, ok)
	}
}

func TestPostgresQueryNormalizedBeforeExport(t *testing.T) {
	q := "SELECT * FROM users WHERE id = 42 AND name = 'bob' AND tag IN (1, 2, 3)"
	msg := append([]byte{'Q', 0, 0, 0, 0}, []byte(q+"\x00")...)
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(msg)-1))
	sp := pair(t, string(msg), "C\x00\x00\x00\x0dSELECT 1\x00")
	got := fmt.Sprint(sp.Attrs["db.query.text"])
	if strings.Contains(got, "42") || strings.Contains(got, "bob") {
		t.Fatalf("literal leaked: %q", got)
	}
	if got != "SELECT * FROM users WHERE id = ? AND name = ? AND tag IN (?+)" {
		t.Fatalf("got %q", got)
	}
	if sp.Attrs["db.system"] != "postgresql" || sp.Name != "SELECT" || sp.Error {
		t.Fatalf("got %+v", sp)
	}
	if b, _ := proto.Marshal(sp.Proto()); bytes.Contains(b, []byte("bob")) {
		t.Fatal("literal in the OTLP span")
	}
}

func TestMySQLAndRedis(t *testing.T) {
	my := []byte{0, 0, 0, 0, 0x03}
	my = append(my, "DELETE FROM t WHERE a = 'x'"...)
	sp := pair(t, string(my), "\x07\x00\x00\x01\xff\x00\x00")
	if sp.Attrs["db.system"] != "mysql" || !sp.Error || strings.Contains(fmt.Sprint(sp.Attrs["db.query.text"]), "'x'") {
		t.Fatalf("mysql: %+v", sp)
	}
	sp = pair(t, "*3\r\n$3\r\nSET\r\n$6\r\nsecret\r\n$5\r\nvalue\r\n", "+OK\r\n")
	if sp.Attrs["db.query.text"] != "SET" || sp.Attrs["db.system"] != "redis" {
		t.Fatalf("redis: %+v", sp)
	}
}

func TestQueryStringStripped(t *testing.T) {
	sp := pair(t, "GET /search?q=secret&token=abc HTTP/1.1\r\nHost: s\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n")
	if sp.Attrs["url.path"] != "/search" {
		t.Fatalf("path %v", sp.Attrs["url.path"])
	}
	if b, _ := proto.Marshal(sp.Proto()); bytes.Contains(b, []byte("secret")) {
		t.Fatal("query string in the span")
	}
	if StripQuery("/a#frag") != "/a" {
		t.Fatal("fragment kept")
	}
}

const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func TestTraceparentExtracted(t *testing.T) {
	sp := pair(t, "GET /a HTTP/1.1\r\ntraceparent: "+tp+"\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n")
	if !sp.HasParent || fmt.Sprintf("%x", sp.TraceID) != "0af7651916cd43dd8448eb211c80319c" || fmt.Sprintf("%x", sp.ParentID) != "b7ad6b7169203331" {
		t.Fatalf("got %x parent %x has=%v", sp.TraceID, sp.ParentID, sp.HasParent)
	}
	if _, ok := ParseTraceparent("00-00000000000000000000000000000000-b7ad6b7169203331-01"); ok {
		t.Fatal("zero trace id accepted")
	}
}

func TestNoSyntheticParentWithoutTraceparent(t *testing.T) {
	sp := pair(t, "GET /a HTTP/1.1\r\nHost: s\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n")
	if sp.HasParent || len(sp.Proto().ParentSpanId) != 0 {
		t.Fatal("parent synthesized without traceparent")
	}
	if sp.TraceID == ([16]byte{}) || sp.SpanID == ([8]byte{}) {
		t.Fatal("span without ids")
	}
	// Two requests without traceparent never share a trace.
	other := pair(t, "GET /a HTTP/1.1\r\nHost: s\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n")
	if other.TraceID == sp.TraceID {
		t.Fatal("unrelated requests share a trace id")
	}
}

func TestEventRateCapDropsAndCounts(t *testing.T) {
	var got int
	c := NewCollector(10, func(uint32) string { return "svc" }, func(_ map[string]string, s []*tracepb.Span) { got += len(s) })
	for i := 0; i < 100; i++ {
		c.Feed(ev(Send, "GET /a HTTP/1.1\r\nHost: s\r\n\r\n"))
		c.Feed(ev(Recv, "HTTP/1.1 200 OK\r\n\r\n"))
	}
	c.Flush()
	if c.Dropped() != 190 || got > 5 {
		t.Fatalf("dropped %d spans %d", c.Dropped(), got)
	}
	// A new second refills the budget.
	l := NewLimiter(1)
	if !l.Allow(t0) || l.Allow(t0) || !l.Allow(t0.Add(time.Second)) || l.Dropped() != 1 {
		t.Fatal("limiter window")
	}
}

func TestAuthorizationHeaderNeverCaptured(t *testing.T) {
	req := "GET /a HTTP/1.1\r\nHost: s\r\nAuthorization: Bearer TOPSECRET\r\nCookie: sid=TOPSECRET\r\n\r\n"
	m, _ := ParseHTTP1([]byte(req))
	if fmt.Sprintf("%+v", m) != fmt.Sprintf("%+v", HTTPMsg{Request: true, Method: "GET", Path: "/a", Authority: "s"}) {
		t.Fatalf("parsed message holds more than the allowlist: %+v", m)
	}
	sp := pair(t, req, "HTTP/1.1 200 OK\r\nSet-Cookie: sid=TOPSECRET\r\n\r\n")
	if b, _ := proto.Marshal(sp.Proto()); bytes.Contains(b, []byte("TOPSECRET")) {
		t.Fatal("credential in the span")
	}
}

func TestProtoTagsEBPF(t *testing.T) {
	p := pair(t, "GET /a HTTP/1.1\r\nHost: s\r\n\r\n", "HTTP/1.1 500 x\r\n\r\n").Proto()
	tags := map[string]string{}
	for _, kv := range p.Attributes {
		tags[kv.Key] = kv.Value.GetStringValue()
	}
	if tags["wt.instrumentation"] != "ebpf" || tags["telemetry.sdk.name"] != "wt-ebpf" || p.Status.Code != 2 {
		t.Fatalf("tags %v status %v", tags, p.Status)
	}
}

func TestNormalizeSQLMatchesWorkerRules(t *testing.T) {
	for in, want := range map[string]string{
		"select 1 -- comment\n from t":             "select ? from t",
		"UPDATE t SET a = $1, b = 'it''s' WHERE x": "UPDATE t SET a = ?, b = ? WHERE x",
		"select /* c */ * from t where a in (1,2)": "select * from t where a in (?+)",
		"select 'unterminated":                     "select ?",
	} {
		if got := NormalizeSQL(in, true); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestParseProcNetTCP(t *testing.T) {
	in := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 0\n"
	m := ParseProcNetTCP(strings.NewReader(in))
	if p := m[4242]; p.Addr != "127.0.0.1" || p.Port != 0xC350 {
		t.Fatalf("got %+v", m)
	}
	if n, ok := SocketInode("socket:[4242]"); !ok || n != 4242 {
		t.Fatal("inode")
	}
}
