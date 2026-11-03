//go:build linux

package ebpf

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const clockTicks = 100 // CLK_TCK on every Linux the agent supports

// Run is the module body: it blocks until ctx ends. endpoint and token come from the agent's
// local config. A disabled module only waits.
func Run(ctx context.Context, raw json.RawMessage, endpoint, token string) error {
	cfg, err := ParseConfig(raw)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		<-ctx.Done()
		return nil
	}
	cfg.Endpoint, cfg.Token = endpoint, token
	if err := Preflight(); err != nil {
		return err
	}
	sess, err := openSession(cfg)
	if err != nil {
		return err
	}
	defer sess.Close()
	guard := Guard{Budget: cfg.CPUBudget, Rate: cfg.SampleHz}
	if err := sess.attachCPU(guard.Rate); err != nil {
		return err
	}
	sess.startRuntimes(ctx)
	host, _ := os.Hostname()
	dotnet := slices.Contains(cfg.RuntimeStacks, "dotnet")
	poster := Poster{Endpoint: cfg.Endpoint, Token: cfg.Token}
	every := time.Duration(cfg.UploadIntervalS) * time.Second
	tick := time.NewTicker(every)
	defer tick.Stop()
	windowStart, lastCPU := time.Now(), selfCPU()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		now := time.Now()
		res := newProcResolver(host, dotnet)
		o := FoldOptions{StripArgs: cfg.Strip(), PlainPID: cfg.PlainPID, Hz: guard.Rate}
		for _, kind := range []Kind{CPU, OffCPU, Lock} {
			upload(ctx, sess, poster, res, kind, windowStart, now.Sub(windowStart), o)
		}
		if sess.rt != nil {
			uploadRuntimes(ctx, sess.rt, poster, res, windowStart, now.Sub(windowStart), o)
		}
		cpu := selfCPU()
		if guard.Observe(cpu-lastCPU, now.Sub(windowStart).Seconds()) {
			slog.Warn("ebpf_profiler over its CPU budget, halving the sample rate", "hz", guard.Rate, "budget", cfg.CPUBudget)
			if err := sess.attachCPU(guard.Rate); err != nil {
				return err
			}
		}
		if sess.rt != nil {
			sess.rt.Govern(guard.Cuts)
		}
		windowStart, lastCPU = now, cpu
	}
}

func upload(ctx context.Context, s *session, p Poster, r Resolver, kind Kind, start time.Time, dur time.Duration, o FoldOptions) {
	entries, err := s.Drain(kind)
	if err != nil {
		Counters.DrainFailures.Add(1)
		slog.Warn("ebpf_profiler drain failed", "kind", kind, "err", err)
		return
	}
	if kind == CPU && s.uw != nil {
		pids := make([]uint32, 0, len(entries))
		for _, e := range entries {
			pids = append(pids, e.PID)
		}
		s.uw.Observe(pids) // tables for the processes sampled now serve the next windows
	}
	if kind == CPU && s.rt != nil {
		for _, e := range entries {
			s.rt.Observe(e.PID)
		}
	}
	profiles, err := Fold(kind, entries, r, start, dur, o)
	if err != nil {
		Counters.FoldFailures.Add(1)
		slog.Warn("ebpf_profiler fold failed", "kind", kind, "err", err)
		return
	}
	for _, pr := range profiles {
		if err := p.Post(ctx, pr); err != nil {
			Counters.UploadsDropped.Add(1)
			slog.Warn("ebpf_profiler upload dropped", "service", pr.Service, "err", err)
			continue
		}
		Counters.Uploads.Add(1)
	}
}

func uploadRuntimes(ctx context.Context, rt *rtSampler, p Poster, r Resolver, start time.Time, dur time.Duration, o FoldOptions) {
	for kind, d := range rt.Drain(r) {
		profiles, err := Fold(kind, d.entries, d.res, start, dur, o)
		if err != nil {
			Counters.FoldFailures.Add(1)
			slog.Warn("ebpf_profiler fold failed", "kind", kind, "err", err)
			continue
		}
		for _, pr := range profiles {
			if err := p.Post(ctx, pr); err != nil {
				Counters.UploadsDropped.Add(1)
				slog.Warn("ebpf_profiler upload dropped", "service", pr.Service, "err", err)
				continue
			}
			Counters.Uploads.Add(1)
		}
	}
}

// selfCPU returns this process's user+system CPU seconds from /proc/self/stat, or 0.
func selfCPU() float64 {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:]) // f[0] is field 3 (state), so utime/stime are f[11], f[12]
	if len(f) < 13 {
		return 0
	}
	u, e1 := strconv.ParseFloat(f[11], 64)
	st, e2 := strconv.ParseFloat(f[12], 64)
	if e1 != nil || e2 != nil {
		return 0
	}
	return (u + st) / clockTicks
}
