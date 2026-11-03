//go:build linux

package trace

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	agentebpf "github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
)

// TestMain doubles as the helper process: the traced server and client must be separate
// processes because the module ignores the agent's own pid.
func TestMain(m *testing.M) {
	switch os.Getenv("WT_TRACE_HELPER") {
	case "server", "tlsserver":
		serveHelper(os.Getenv("WT_TRACE_HELPER") == "tlsserver")
	case "client", "tlsclient":
		clientHelper(os.Getenv("WT_TRACE_HELPER") == "tlsclient", os.Getenv("WT_TRACE_ADDR"))
	default:
		os.Exit(m.Run())
	}
}

func serveHelper(useTLS bool) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	if useTLS {
		s := httptest.NewTLSServer(h)
		fmt.Println(s.Listener.Addr().String())
	} else {
		s := httptest.NewServer(h)
		fmt.Println(s.Listener.Addr().String())
	}
	_, _ = io.Copy(io.Discard, os.Stdin) // lives until the test closes stdin
	os.Exit(0)
}

func clientHelper(useTLS bool, addr string) {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test
	scheme, path := "http", "/hello?x=1"
	if useTLS {
		scheme, path = "https", "/secure?x=1"
	}
	time.Sleep(500 * time.Millisecond) // let the module settle
	resp, err := c.Get(scheme + "://" + addr + path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(time.Second)
	os.Exit(0)
}

type got struct {
	mu    sync.Mutex
	spans []*tracepb.Span
}

func (g *got) sink(_ map[string]string, s []*tracepb.Span) {
	g.mu.Lock()
	g.spans = append(g.spans, s...)
	g.mu.Unlock()
}

func (g *got) find(kind tracepb.Span_SpanKind, path string) *tracepb.Span {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.spans {
		if s.Kind != kind {
			continue
		}
		for _, kv := range s.Attributes {
			if kv.Key == "url.path" && kv.Value.GetStringValue() == path {
				return s
			}
		}
	}
	return nil
}

func attrOf(s *tracepb.Span, key string) (string, int64) {
	for _, kv := range s.Attributes {
		if kv.Key == key {
			return kv.Value.GetStringValue(), kv.Value.GetIntValue()
		}
	}
	return "", 0
}

// startModule skips unless the host can run it, then runs ebpf_trace until the test ends.
func startModule(t *testing.T, tlsOn bool) *got {
	t.Helper()
	if err := agentebpf.Preflight(); err != nil {
		t.Skipf("eBPF not available: %v", err)
	}
	dir := os.Getenv("WT_EBPF_OBJ")
	if dir == "" {
		dir = "/usr/lib/wt-agent/ebpf"
	}
	if _, err := os.Stat(filepath.Join(dir, "http_bpfel.o")); err != nil {
		t.Skipf("BPF objects missing (run make ebpf-gen on Linux, set WT_EBPF_OBJ): %v", err)
	}
	raw, _ := json.Marshal(map[string]any{"enabled": true, "object_dir": dir, "tls": tlsOn})
	g := &got{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, raw, g.sink, nil, nil) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return g
}

// helpers starts the server child and runs the client child against it.
func helpers(t *testing.T, mode string) {
	t.Helper()
	srv := exec.Command(os.Args[0])
	srv.Env = append(os.Environ(), "WT_TRACE_HELPER="+mode+"server")
	in, _ := srv.StdinPipe()
	out, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = srv.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(addr[:len(addr)-1])
	cli := exec.Command(os.Args[0])
	cli.Env = append(os.Environ(), "WT_TRACE_HELPER="+mode+"client", "WT_TRACE_ADDR="+net.JoinHostPort(host, port))
	if b, err := cli.CombinedOutput(); err != nil {
		t.Fatalf("client: %v %s", err, b)
	}
}

func waitSpan(t *testing.T, g *got, kind tracepb.Span_SpanKind, path string) *tracepb.Span {
	t.Helper()
	for i := 0; i < 50; i++ {
		if s := g.find(kind, path); s != nil {
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no %v span for %s", kind, path)
	return nil
}

func TestHTTPSpanForLocalServer(t *testing.T) {
	g := startModule(t, false)
	helpers(t, "")
	for _, k := range []tracepb.Span_SpanKind{tracepb.Span_SPAN_KIND_CLIENT, tracepb.Span_SPAN_KIND_SERVER} {
		s := waitSpan(t, g, k, "/hello") // the query string must already be gone
		if m, _ := attrOf(s, "http.request.method"); m != "GET" {
			t.Errorf("kind %v method %q", k, m)
		}
		if _, st := attrOf(s, "http.response.status_code"); st != 200 {
			t.Errorf("kind %v status %d", k, st)
		}
	}
}

func TestTLSUprobeSeesGoTLSRequest(t *testing.T) {
	g := startModule(t, true)
	time.Sleep(time.Second) // first uprobe scan
	helpers(t, "tls")
	waitSpan(t, g, tracepb.Span_SPAN_KIND_SERVER, "/secure")
}
