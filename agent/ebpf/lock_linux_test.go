//go:build linux

package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLockContentionSeesBlockedAcquire holds a Python lock for 1 s in one thread while another
// blocks on it; the blocked acquire is an untimed futex wait (or a hooked pthread call).
func TestLockContentionSeesBlockedAcquire(t *testing.T) {
	if err := Preflight(); err != nil {
		t.Skipf("eBPF not available: %v", err)
	}
	dir := os.Getenv("WT_EBPF_OBJECTS")
	if dir == "" {
		dir = "."
	}
	if _, err := os.Stat(filepath.Join(dir, "lock_bpfel.o")); err != nil {
		t.Skipf("lock_bpfel.o missing in %s (run make ebpf-gen on Linux): %v", dir, err)
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	cfg, _ := ParseConfig([]byte(`{"enabled":true,"offcpu":false,"lock_contention":true,"lock_futex":true}`))
	cfg.ObjectDir = dir
	s, err := openSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	script := `import threading, time
l = threading.Lock(); l.acquire()
t = threading.Thread(target=lambda: (l.acquire(), l.release())); t.start()
time.sleep(1); l.release(); t.join()`
	child := exec.Command(py, "-c", script)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(child.Process.Pid)
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	es, err := s.Drain(Lock)
	if err != nil {
		t.Fatal(err)
	}
	got := time.Duration(sumFor(es, pid))
	if got < 800*time.Millisecond || got > 2*time.Second {
		t.Fatalf("lock wait = %v, want about 1s", got)
	}
}
