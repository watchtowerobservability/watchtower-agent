package snmp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Config is the snmp module's config. Remote config may only set Enabled and Interval; targets,
// credentials, the manifest directory and the trap listener exist only in the agent's file.
type Config struct {
	Enabled     *bool       `json:"enabled"`
	Interval    string      `json:"interval"`     // default 60s, at least 10s
	PollTimeout string      `json:"poll_timeout"` // deadline for one device's whole poll, default 30s
	ManifestDir string      `json:"manifest_dir"` // extra or replacement manifests
	Targets     []Target    `json:"targets"`
	Trap        *TrapConfig `json:"trap"`
}

type job struct {
	t  Target
	ms []Manifest
}

// pollAll polls every device at once. Each has its own deadline, so a stuck one delays only
// itself.
func pollAll(ctx context.Context, jobs []job, rates *Rates, out sink.Sink, deadline time.Duration) {
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, deadline)
			defer cancel()
			done := make(chan error, 1)
			at := time.Now()
			go func() { done <- PollTarget(dctx, j.t, j.ms, rates, out, at) }()
			select {
			case err := <-done:
				if err != nil {
					slog.Warn("snmp poll failed", "device", j.t.Name, "error", err)
				}
			case <-dctx.Done():
				out.Gauge("snmp.device.up", "1", 0, map[string]string{"snmp.device": j.t.Name}, at)
				slog.Warn("snmp poll timed out", "device", j.t.Name)
			}
		}()
	}
	wg.Wait()
}

// Run polls and listens until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("snmp config: %w", err)
		}
	}
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 && c.Trap == nil {
		<-ctx.Done()
		return nil
	}
	all, err := Manifests(c.ManifestDir)
	if err != nil {
		return err
	}
	var jobs []job
	for _, t := range c.Targets {
		if err := t.Validate(); err != nil {
			return err
		}
		ms, err := pick(all, t.Manifests)
		if err != nil {
			return fmt.Errorf("snmp target %q: %w", t.Name, err)
		}
		jobs = append(jobs, job{t, ms})
	}
	// The trap listener is independent of polling: it may fail to bind (port 162 needs
	// privileges) without stopping the polls.
	var wg sync.WaitGroup
	defer wg.Wait()
	if c.Trap != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			trapLoop(ctx, *c.Trap, out)
		}()
	}
	every := host.Duration(c.Interval, 60*time.Second, 10*time.Second)
	deadline := min(host.Duration(c.PollTimeout, 30*time.Second, time.Second), every)
	rates := &Rates{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		pollAll(ctx, jobs, rates, out, deadline)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
