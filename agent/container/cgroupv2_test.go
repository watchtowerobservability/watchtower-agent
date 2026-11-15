package container

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func writeCG(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScanCgroupsBothLayoutsAndCollect(t *testing.T) {
	root := t.TempDir()
	a, b := "a"+repeat("1", 63), repeat("b", 64)
	files := map[string]string{
		"cpu.stat": "usage_usec 2000\nuser_usec 1\n", "memory.current": "1000\n", "memory.max": "4096\n",
		"memory.stat": "anon 600\nfile 300\ninactive_file 100\n", "pids.current": "7\n",
		"io.stat": "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n8:16 rbytes=5 wbytes=5\n",
	}
	writeCG(t, filepath.Join(root, "system.slice", "docker-"+a+".scope"), files)
	writeCG(t, filepath.Join(root, "docker", b), map[string]string{"cpu.stat": "usage_usec 1\n", "memory.current": "5\n", "memory.max": "max\n"})
	got := ScanCgroups(root)
	if len(got) != 2 {
		t.Fatalf("want 2 containers, got %+v", got)
	}
	by := map[string]CG{got[0].ID: got[0], got[1].ID: got[1]}
	c := by[a]
	if c.CPUUsageNS != 2_000_000 || c.MemBytes != 900 || c.MemLimit != 4096 || c.MemAnon != 600 || c.MemFile != 300 || !c.HasPids || c.Pids != 7 || c.IORead != 15 || c.IOWrite != 25 {
		t.Fatalf("reading: %+v", c)
	}
	if d := by[b]; d.MemLimit != 0 || d.HasPids || d.HasIO {
		t.Fatalf("bare layout: %+v", d)
	}

	names := filepath.Join(t.TempDir(), "names")
	_ = os.WriteFile(names, []byte("# comment\n"+a[:12]+" web\n"), 0o644)
	t.Setenv("WT_AGENT_CONTAINER_NAMES", names)
	var r sink.Recorder
	(&Poller{}).CollectCgroups(root, map[string]bool{}, &r)
	seen := map[string]string{}
	for _, s := range r.Samples {
		if s.Attrs["container.id"] == a {
			seen[s.Name] = s.Attrs["container.name"]
		}
	}
	for _, n := range []string{"container.memory.usage", "container.memory.limit", "container.memory.anon", "container.pids.count", "container.blockio.read"} {
		if seen[n] != "web" {
			t.Fatalf("%s: name %q (all: %v)", n, seen[n], seen)
		}
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
