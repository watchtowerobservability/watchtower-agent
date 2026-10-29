//go:build linux

package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	capSysAdmin = 21
	capPerfmon  = 38
	capBPF      = 39
	maxDepth    = 127
)

// Preflight checks kernel version, BTF and privileges, with a message that says what to fix.
func Preflight() error {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return err
	}
	rel := unix.ByteSliceToString(u.Release[:])
	if !kernelAtLeast(rel, 5, 8) {
		return fmt.Errorf("ebpf profiler needs Linux >= 5.8, this host runs %s", rel)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return errors.New("ebpf profiler needs a kernel built with BTF (/sys/kernel/btf/vmlinux is missing)")
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	if !hasProfilingCaps(string(b)) {
		return errors.New("ebpf profiler needs root, or CAP_BPF and CAP_PERFMON (CAP_SYS_ADMIN on kernels < 5.8)")
	}
	return nil
}

func kernelAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, e1 := strconv.Atoi(parts[0])
	mi, e2 := strconv.Atoi(strings.TrimRight(strings.SplitN(parts[1], "-", 2)[0], "+"))
	if e1 != nil || e2 != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

// hasProfilingCaps reads the CapEff line of /proc/self/status.
func hasProfilingCaps(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		v, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return false
		}
		has := func(bit uint) bool { return eff&(1<<bit) != 0 }
		return has(capSysAdmin) || (has(capBPF) && has(capPerfmon))
	}
	return false
}

// countKey mirrors `struct key` in bpf/common.h.
type countKey struct {
	PID  uint32
	User int32
	Kern int32
}

type objects struct {
	coll   *ebpf.Collection
	counts *ebpf.Map
	stacks *ebpf.Map
}

func (o *objects) close() {
	if o != nil && o.coll != nil {
		o.coll.Close()
	}
}

func loadObjects(dir, name string, minNs uint64) (*objects, error) {
	spec, err := ebpf.LoadCollectionSpec(filepath.Join(dir, name+"_bpfel.o"))
	if err != nil {
		return nil, fmt.Errorf("%w (build the objects with `make ebpf-gen` and install them into object_dir)", err)
	}
	if minNs > 0 {
		if v, ok := spec.Variables["min_ns"]; ok {
			if err := v.Set(minNs); err != nil {
				return nil, err
			}
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	return &objects{coll: coll, counts: coll.Maps["counts"], stacks: coll.Maps["stacks"]}, nil
}

// drain reads and clears the count map, joining each key with its stack addresses.
func (o *objects) drain() ([]Entry, error) {
	type row struct {
		k countKey
		v uint64
	}
	var rows []row
	var k countKey
	var v uint64
	it := o.counts.Iterate()
	for it.Next(&k, &v) {
		rows = append(rows, row{k, v})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(rows))
	for _, r := range rows {
		_ = o.counts.Delete(r.k) // a sample landing between iterate and delete is lost, not double counted
		out = append(out, Entry{PID: r.k.PID, User: o.stack(r.k.User), Kernel: o.stack(r.k.Kern), Value: r.v})
	}
	return out, nil
}

func (o *objects) stack(id int32) []uint64 {
	if id < 0 {
		return nil
	}
	var st [maxDepth]uint64
	if err := o.stacks.Lookup(uint32(id), &st); err != nil {
		return nil
	}
	n := 0
	for n < maxDepth && st[n] != 0 {
		n++
	}
	return st[:n]
}

// session holds the loaded programs and their attachments.
type session struct {
	cfg Config
	cpu *objects
	off *objects
	fds []int
	tp  link.Link
}

func openSession(cfg Config) (*session, error) {
	s := &session{cfg: cfg}
	var err error
	if s.cpu, err = loadObjects(cfg.ObjectDir, "cpu", 0); err != nil {
		return nil, err
	}
	if cfg.OffCPU {
		if s.off, err = loadObjects(cfg.ObjectDir, "offcpu", uint64(cfg.OffCPUMinMs)*1_000_000); err != nil {
			s.Close()
			return nil, err
		}
		if s.tp, err = link.Tracepoint("sched", "sched_switch", s.off.coll.Programs["on_switch"], nil); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// attachCPU (re)opens one sampling perf event per online CPU at hz.
func (s *session) attachCPU(hz int) error {
	s.closeFDs()
	prog := s.cpu.coll.Programs["on_cpu"]
	for _, cpu := range onlineCPUs() {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: uint64(hz),
			Bits:   unix.PerfBitFreq,
		}
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			s.closeFDs()
			return fmt.Errorf("perf_event_open cpu %d: %w", cpu, err)
		}
		s.fds = append(s.fds, fd)
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
			s.closeFDs()
			return fmt.Errorf("attach program to cpu %d: %w", cpu, err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			s.closeFDs()
			return err
		}
	}
	return nil
}

func (s *session) closeFDs() {
	for _, fd := range s.fds {
		_ = unix.Close(fd)
	}
	s.fds = nil
}

// Drain returns and clears the counts of one kind.
func (s *session) Drain(kind Kind) ([]Entry, error) {
	if kind == OffCPU {
		if s.off == nil {
			return nil, nil
		}
		return s.off.drain()
	}
	return s.cpu.drain()
}

// Close detaches everything.
func (s *session) Close() {
	s.closeFDs()
	if s.tp != nil {
		s.tp.Close()
	}
	s.cpu.close()
	s.off.close()
}

// onlineCPUs parses /sys/devices/system/cpu/online ("0-3,6"); it falls back to 0..NumCPU-1.
func onlineCPUs() []int {
	f, err := os.Open("/sys/devices/system/cpu/online")
	if err == nil {
		defer f.Close()
		line, _ := bufio.NewReader(f).ReadString('\n')
		if cpus := parseCPUList(strings.TrimSpace(line)); len(cpus) > 0 {
			return cpus
		}
	}
	n := runtime.NumCPU()
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func parseCPUList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil
			}
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
	}
	return out
}
