package container

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestDockerStatsFromFakeSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket test")
	}
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	cpu := 1_000_000_000
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Id":"abcdef0123456789","Names":["/web"],"Image":"nginx:1"}]`))
	})
	mux.HandleFunc("/containers/abcdef0123456789/stats", func(w http.ResponseWriter, _ *http.Request) {
		cpu += 500_000_000
		_, _ = w.Write([]byte(`{"cpu_stats":{"cpu_usage":{"total_usage":` + strconv.Itoa(cpu) + `}},
			"memory_stats":{"usage":1000,"stats":{"inactive_file":400}}}`))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = l
	srv.Start()
	defer srv.Close()

	d, err := NewDocker("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	var r sink.Recorder
	p := &Poller{}
	if _, err := p.Collect(context.Background(), d, &r); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := p.Collect(context.Background(), d, &r); err != nil {
		t.Fatal(err)
	}
	var mem, cores float64
	for _, s := range r.Samples {
		if s.Attrs["container.id"] != "abcdef0123456789" || s.Attrs["container.name"] != "web" || s.Attrs["container.image.name"] != "nginx:1" {
			t.Fatalf("attrs: %v", s.Attrs)
		}
		switch s.Name {
		case "container.memory.usage":
			mem = s.Value
		case "container.cpu.usage":
			cores = s.Value
		}
	}
	if mem != 600 {
		t.Fatalf("memory is usage minus inactive_file: %v", mem)
	}
	if cores <= 0 {
		t.Fatalf("cpu cores from the delta: %v", cores)
	}
	if _, err := NewDocker("tcp://x:2375"); err == nil {
		t.Fatal("tcp endpoints must be refused")
	}
}

func TestCgroupV2Parse(t *testing.T) {
	if n, ok := ParseCPUStat("usage_usec 2500\nuser_usec 1\n"); !ok || n != 2_500_000 {
		t.Fatalf("cpu.stat: %d %v", n, ok)
	}
	if ParseMemoryStat("anon 5\ninactive_file 300\n", "inactive_file") != 300 {
		t.Fatal("memory.stat")
	}
	root := t.TempDir()
	id := strings.Repeat("ab", 32)
	dir := filepath.Join(root, "system.slice", "libpod-"+id+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("cpu.stat", "usage_usec 1000\n")
	must("memory.current", "5000\n")
	must("memory.stat", "inactive_file 1000\n")
	got := ScanCgroups(root)
	if len(got) != 1 || got[0].ID != id || got[0].CPUUsageNS != 1_000_000 || got[0].MemBytes != 4000 {
		t.Fatalf("scan: %+v", got)
	}
}
