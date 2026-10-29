package host

import (
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MaxProcesses caps each process list (top by CPU, top by memory). Live agent-served process
// views are known gap G-24; this is sampled metrics only.
const MaxProcesses = 50

// ProcSample is one process at one sample.
type ProcSample struct {
	PID     int32
	Name    string
	CPUSecs float64 // cumulative user+system seconds
	RSS     uint64
}

// TopN returns at most MaxProcesses samples with the largest key, largest first. Ties break by
// pid so the result is stable.
func TopN(in []ProcSample, key func(ProcSample) float64) []ProcSample {
	s := append([]ProcSample(nil), in...)
	sort.Slice(s, func(i, j int) bool {
		if ki, kj := key(s[i]), key(s[j]); ki != kj {
			return ki > kj
		}
		return s[i].PID < s[j].PID
	})
	if len(s) > MaxProcesses {
		s = s[:MaxProcesses]
	}
	return s
}

// Processes samples the process table on its own, slower, schedule.
type Processes struct {
	every time.Duration
	last  time.Time
	prev  map[int32]float64
}

// NewProcesses returns a sampler that runs at most once per every.
func NewProcesses(every time.Duration) *Processes {
	return &Processes{every: every, prev: map[int32]float64{}}
}

// Maybe samples when due. It is safe on a nil receiver (processes disabled).
func (p *Processes) Maybe(out sink.Sink, now time.Time) {
	if p == nil || (!p.last.IsZero() && now.Sub(p.last) < p.every-time.Second) {
		return
	}
	elapsed := now.Sub(p.last)
	first := p.last.IsZero()
	p.last = now
	list, err := process.Processes()
	if err != nil {
		return
	}
	samples := make([]ProcSample, 0, len(list))
	for _, pr := range list {
		s := ProcSample{PID: pr.Pid}
		s.Name, _ = pr.Name()
		if t, err := pr.Times(); err == nil {
			s.CPUSecs = t.User + t.System
		}
		if m, err := pr.MemoryInfo(); err == nil && m != nil {
			s.RSS = m.RSS
		}
		samples = append(samples, s)
	}
	if first {
		elapsed = 0 // no CPU delta yet
	}
	p.prev = EmitProcesses(out, samples, p.prev, elapsed, now)
}

// EmitProcesses writes process.cpu.utilization for the top processes by CPU (a fraction of all
// cores, from the change since prev over elapsed) and process.memory.usage for the top by
// memory. It returns the new cumulative CPU map.
func EmitProcesses(out sink.Sink, samples []ProcSample, prev map[int32]float64, elapsed time.Duration, at time.Time) map[int32]float64 {
	next := make(map[int32]float64, len(samples))
	delta := make(map[int32]float64, len(samples))
	for _, s := range samples {
		next[s.PID] = s.CPUSecs
		if before, ok := prev[s.PID]; ok && elapsed > 0 && s.CPUSecs >= before {
			delta[s.PID] = (s.CPUSecs - before) / elapsed.Seconds() / float64(runtime.NumCPU())
		}
	}
	attrs := func(s ProcSample) map[string]string {
		return map[string]string{
			"process.pid":             strconv.Itoa(int(s.PID)),
			"process.executable.name": s.Name,
		}
	}
	if elapsed > 0 {
		for _, s := range TopN(samples, func(s ProcSample) float64 { return delta[s.PID] }) {
			out.Gauge("process.cpu.utilization", "1", delta[s.PID], attrs(s), at)
		}
	}
	for _, s := range TopN(samples, func(s ProcSample) float64 { return float64(s.RSS) }) {
		out.Gauge("process.memory.usage", "By", float64(s.RSS), attrs(s), at)
	}
	return next
}
