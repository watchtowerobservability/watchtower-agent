//go:build linux

package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestKernelHelpers(t *testing.T) {
	if !kernelAtLeast("5.15.0-91-generic", 5, 8) || kernelAtLeast("5.4.0", 5, 8) || !kernelAtLeast("6.1.0", 5, 8) {
		t.Fatal("kernelAtLeast")
	}
	if !hasProfilingCaps("Name:\tx\nCapEff:\t000000c000000000\n") || hasProfilingCaps("CapEff:\t0000000000000000\n") {
		t.Fatal("hasProfilingCaps")
	}
	if got := parseCPUList("0-2,5"); len(got) != 4 || got[3] != 5 {
		t.Fatalf("cpu list = %v", got)
	}
}

// itSession opens a real session or skips: it needs root, kernel >= 5.8 with BTF, and the
// objects built by `make ebpf-gen` (WT_EBPF_OBJECTS or the default object_dir).
func itSession(t *testing.T, hz int) *session {
	t.Helper()
	if err := Preflight(); err != nil {
		t.Skipf("eBPF not available: %v", err)
	}
	dir := os.Getenv("WT_EBPF_OBJECTS")
	if dir == "" {
		dir = "."
	}
	if _, err := os.Stat(filepath.Join(dir, "cpu_bpfel.o")); err != nil {
		t.Skipf("BPF objects missing in %s (run make ebpf-gen on Linux): %v", dir, err)
	}
	cfg, _ := ParseConfig([]byte(`{"enabled":true}`))
	cfg.ObjectDir = dir
	s, err := openSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.attachCPU(hz); err != nil {
		t.Fatal(err)
	}
	return s
}

func sumFor(es []Entry, pid uint32) (v uint64) {
	for _, e := range es {
		if e.PID == pid {
			v += e.Value
		}
	}
	return v
}

func TestCpuProfilerSeesBusyLoop(t *testing.T) {
	s := itSession(t, 19)
	child := exec.Command("sh", "-c", "while :; do :; done")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	time.Sleep(3 * time.Second)
	es, err := s.Drain(CPU)
	if err != nil {
		t.Fatal(err)
	}
	got := sumFor(es, uint32(child.Process.Pid))
	// one busy CPU at 19 Hz for 3 s is about 57 samples; allow for scheduling noise
	if got < 25 || got > 80 {
		t.Fatalf("samples for busy child = %d, want about 57", got)
	}
}

func TestOffCpuSeesSleep(t *testing.T) {
	s := itSession(t, 19)
	child := exec.Command("sleep", "1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(child.Process.Pid)
	_ = child.Wait()
	es, err := s.Drain(OffCPU)
	if err != nil {
		t.Fatal(err)
	}
	got := time.Duration(sumFor(es, pid))
	if got < 800*time.Millisecond || got > 1200*time.Millisecond {
		t.Fatalf("off-CPU time = %v, want about 1s", got)
	}
}
