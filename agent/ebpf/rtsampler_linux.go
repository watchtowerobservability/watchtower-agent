//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	rtMaxProcs      = 32
	rtRegReads      = 256 // reads for the walk of one register sample, out of the tick's cap
	rtAttachReads   = 1 << 18
	rtProbeAttempts = 3
	rtProbeSlots    = 2 // concurrent attaches; each parses an ELF file
)

type rtProc struct {
	w    stackWalker
	kind Kind
}

// rtSampler reads the stacks of runtimes in the processes the CPU profiler sees. Each pid is
// probed at most rtProbeAttempts times; a refusal is logged once with its reason; a process that
// stops answering is forgotten.
type rtSampler struct {
	mu      sync.Mutex
	enabled map[string]bool
	procs   map[uint32]*rtProc
	tries   map[uint32]int
	busy    map[uint32]bool
	folders map[Kind]*pyFolder
	left    int
	regLeft int
	cuts    int
	slots   chan struct{}
	watch   *ebpf.Map // rt_pids, nil without register samples
}

func newRTSampler(enabled map[string]bool) *rtSampler {
	return &rtSampler{enabled: enabled, procs: map[uint32]*rtProc{}, tries: map[uint32]int{}, busy: map[uint32]bool{}, folders: map[Kind]*pyFolder{}, slots: make(chan struct{}, rtProbeSlots)}
}

// Observe queues pid for a probe; it does not block the caller on ELF parsing.
func (s *rtSampler) Observe(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tries[pid] >= rtProbeAttempts || s.procs[pid] != nil || len(s.procs) >= rtMaxProcs {
		return
	}
	if s.busy[pid] {
		return
	}
	s.busy[pid] = true
	go s.probe(pid)
}

func (s *rtSampler) probe(pid uint32) {
	s.slots <- struct{}{}
	defer func() { <-s.slots }()
	attach := rtAttachReads
	mem := &budgetMem{pidMem(pid), &attach}
	w, rt, err := attachWithRetry(pid, mem, s.enabled)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, pid)
	s.tries[pid]++
	switch {
	case err != nil && errors.Is(err, errNotReady) && s.tries[pid] < rtProbeAttempts:
		// a later window tries again
	case err != nil:
		s.tries[pid] = rtProbeAttempts
		slog.Info("ebpf_profiler: runtime stacks refused", "pid", pid, "reason", err)
	case w == nil:
		s.tries[pid] = rtProbeAttempts // runs no enabled runtime
	default:
		mem.left = &s.left // from now on reads share the tick's budget
		s.procs[pid] = &rtProc{w: w, kind: rt.kind}
		if _, ok := w.(regWalker); ok && s.watch != nil {
			if err := s.watch.Put(pid, uint8(1)); err != nil {
				slog.Warn("ebpf_profiler: register samples unavailable", "pid", pid, "err", err)
			}
		}
	}
}

// attachWithRetry retries a torn or too-early attach briefly; the target keeps running.
func attachWithRetry(pid uint32, mem memReader, enabled map[string]bool) (stackWalker, *rtRuntime, error) {
	var last error
	for range 3 {
		w, rt, err := attachRuntime(pid, mem, enabled)
		if err == nil {
			return w, rt, nil
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	return nil, nil, last
}

func (s *rtSampler) forget(pid uint32) {
	delete(s.procs, pid)
	delete(s.tries, pid) // a reused pid may be probed again
	if s.watch != nil {
		_ = s.watch.Delete(pid)
	}
}

func (s *rtSampler) add(pid uint32, kind Kind, frames []string) {
	f := s.folders[kind]
	if f == nil {
		f = newPyFolder()
		s.folders[kind] = f
	}
	f.add(pid, frames)
}

// Govern applies the CPU guard's cuts to the read caps.
func (s *rtSampler) Govern(cuts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cuts = cuts
}

// Run samples until ctx ends.
func (s *rtSampler) Run(ctx context.Context) {
	t := time.NewTicker(time.Second / pyHz)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.tick()
	}
}

func (s *rtSampler) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.left, s.regLeft = rtReadCap(s.cuts), rtReadCap(s.cuts)
	for pid, p := range s.procs {
		if s.left <= 0 {
			return // map order is random, so the next tick starts with another process
		}
		stacks, err := p.w.Stacks()
		if err != nil && len(stacks) == 0 && !errors.Is(err, errBudget) {
			s.forget(pid)
			continue
		}
		for _, st := range stacks {
			s.add(pid, p.kind, st.Frames)
		}
	}
}

// onRegs handles one register sample of a watched process.
func (s *rtSampler) onRegs(pid uint32, pc, sp, fp uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.procs[pid]
	if p == nil || s.regLeft <= 0 {
		return
	}
	if w, ok := p.w.(regWalker); ok {
		given := min(rtRegReads, s.regLeft)
		s.left = given
		if fr := w.StackFrom(pc, sp, fp); len(fr) > 0 {
			s.add(pid, p.kind, fr)
		}
		s.regLeft -= given - s.left
		s.left = 0
	}
}

type rtDrained struct {
	entries []Entry
	res     Resolver
}

// Drain returns the window's stacks per kind. Name caches restart with the window.
func (s *rtSampler) Drain(r Resolver) map[Kind]rtDrained {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[Kind]rtDrained, len(s.folders))
	for k, f := range s.folders {
		out[k] = rtDrained{f.entries(), pyResolver{Resolver: r, names: f.names}}
	}
	s.folders = map[Kind]*pyFolder{}
	if len(s.tries) > 1<<14 { // dead pids; a live refused one is probed and logged once more
		s.tries = map[uint32]int{}
	}
	for _, p := range s.procs {
		p.w.resetNames()
	}
	return out
}

// startRuntimes starts the sampler when any runtime is enabled. Register samples are for Node and
// JVM only, and failing to load them leaves everything else working.
func (s *session) startRuntimes(ctx context.Context) {
	enabled := map[string]bool{"python": s.cfg.PythonStacks}
	regs := false
	readers := false
	for _, r := range s.cfg.RuntimeStacks {
		enabled[r] = true
		regs = regs || r == "node" || r == "jvm"
		readers = readers || r != "dotnet" // .NET is named through its perf map, by the resolver
	}
	if !enabled["python"] && !readers {
		return
	}
	s.rt = newRTSampler(enabled)
	if regs {
		if err := s.startRegSamples(ctx); err != nil {
			slog.Warn("ebpf_profiler: no register samples: Node stacks and on-CPU JVM stacks are off", "err", err)
		}
	}
	go s.rt.Run(ctx)
}

func (s *session) startRegSamples(ctx context.Context) error {
	coll, err := loadRegs(s.cfg.ObjectDir)
	if err != nil {
		return err
	}
	var fds []int
	stop := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		coll.Close()
	}
	if fds, err = openPerfEvents(coll.Programs["on_cpu"], pyHz); err != nil {
		stop()
		return err
	}
	rd, err := ringbuf.NewReader(coll.Maps["rt_events"])
	if err != nil {
		stop()
		return err
	}
	s.rt.watch = coll.Maps["rt_pids"]
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	go func() {
		defer stop()
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			var e struct {
				PID, TID   uint32
				PC, SP, FP uint64
			}
			if binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e) == nil {
				s.rt.onRegs(e.PID, e.PC, e.SP, e.FP)
			}
		}
	}()
	return nil
}

func loadRegs(dir string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(filepath.Join(dir, "rtregs_bpfel.o"))
	if err != nil {
		return nil, err
	}
	if err := setTaskRegs(spec); err != nil {
		return nil, err
	}
	return ebpf.NewCollection(spec)
}
