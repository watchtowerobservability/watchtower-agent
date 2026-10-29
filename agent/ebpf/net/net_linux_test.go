//go:build linux

package net

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	agentebpf "github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
)

const transfer = 8 << 20

// TestMain doubles as the helper: a server that sends `transfer` bytes and a client reading them.
func TestMain(m *testing.M) {
	switch os.Getenv("WT_NET_HELPER") {
	case "server":
		l, _ := stdnet.Listen("tcp", "127.0.0.1:0")
		fmt.Println(l.Addr().String())
		c, err := l.Accept()
		if err != nil {
			os.Exit(1)
		}
		_, _ = c.Write(make([]byte, transfer))
		c.Close()
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "client":
		c, err := stdnet.Dial("tcp", os.Getenv("WT_NET_ADDR"))
		if err != nil {
			os.Exit(1)
		}
		_, _ = io.Copy(io.Discard, c)
		c.Close()
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type sums struct {
	mu sync.Mutex
	m  map[string]float64
}

func (s *sums) Gauge(string, string, float64, map[string]string, time.Time) {}
func (s *sums) Log(string, string, map[string]string, time.Time)            {}
func (s *sums) Sum(n, _ string, v float64, a map[string]string, _ time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[n+"|"+a["server.port"]] = v
}

func TestTCPMetricsForLoopbackTransfer(t *testing.T) {
	if err := agentebpf.Preflight(); err != nil {
		t.Skipf("eBPF not available: %v", err)
	}
	dir := os.Getenv("WT_EBPF_OBJ")
	if dir == "" {
		dir = "/usr/lib/wt-agent/ebpf"
	}
	if _, err := os.Stat(filepath.Join(dir, "tcp_bpfel.o")); err != nil {
		t.Skipf("BPF objects missing (run make ebpf-gen on Linux, set WT_EBPF_OBJ): %v", err)
	}
	out := &sums{m: map[string]float64{}}
	raw, _ := json.Marshal(map[string]any{"enabled": true, "object_dir": dir, "interval": "1s", "dns": false})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, raw, out) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(time.Second)

	srv := exec.Command(os.Args[0])
	srv.Env = append(os.Environ(), "WT_NET_HELPER=server")
	in, _ := srv.StdinPipe()
	so, _ := srv.StdoutPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); _ = srv.Wait() })
	addr, err := bufio.NewReader(so).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	addr = strings.TrimSpace(addr)
	_, port, _ := stdnet.SplitHostPort(addr)
	cli := exec.Command(os.Args[0])
	cli.Env = append(os.Environ(), "WT_NET_HELPER=client", "WT_NET_ADDR="+addr)
	if b, err := cli.CombinedOutput(); err != nil {
		t.Fatalf("client: %v %s", err, b)
	}
	key := "wt.net.tcp.bytes_received|" + port
	var got float64
	for i := 0; i < 30 && got == 0; i++ {
		time.Sleep(200 * time.Millisecond)
		out.mu.Lock()
		got = out.m[key]
		out.mu.Unlock()
	}
	p, _ := strconv.Atoi(port)
	if lo, hi := transfer*0.95, transfer*1.05; got < lo || got > hi {
		t.Fatalf("bytes_received on port %d = %v, want within 5%% of %d", p, got, transfer)
	}
}
