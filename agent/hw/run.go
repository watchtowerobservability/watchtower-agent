package hw

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

// Config is the hw module's config. Remote config may only set Enabled and Interval.
type Config struct {
	Enabled     *bool     `json:"enabled"`
	Interval    string    `json:"interval"`     // default 60s, at least 15s
	PollTimeout string    `json:"poll_timeout"` // deadline per device, default 30s
	Redfish     []Redfish `json:"redfish"`
	IPMI        []IPMI    `json:"ipmi"`
	NUT         []NUT     `json:"nut"`
	SSH         []SSHHost `json:"ssh"`    // SMART, NVMe and md RAID over SSH (pinned host key)
	Arrays      []Array   `json:"arrays"` // storage arrays: NetApp ONTAP, Pure FlashArray, Dell PowerStore/Unity, HPE 3PAR/Primera/Nimble, IBM FlashSystem
}

type task struct {
	kind, name string
	run        func(context.Context, sink.Sink, time.Time) error
}

func (c Config) tasks() []task {
	var ts []task
	for _, r := range c.Redfish {
		ts = append(ts, task{"redfish", r.Name, func(ctx context.Context, o sink.Sink, at time.Time) error { return PollRedfish(ctx, r, o, at) }})
	}
	for _, i := range c.IPMI {
		if !i.Available() {
			slog.Info("ipmi disabled: ipmitool not found at the configured path", "device", i.Name)
			continue
		}
		ts = append(ts, task{"ipmi", i.Name, func(ctx context.Context, o sink.Sink, at time.Time) error { return PollIPMI(ctx, i, o, at) }})
	}
	for _, n := range c.NUT {
		ts = append(ts, task{"nut", n.Name, func(ctx context.Context, o sink.Sink, at time.Time) error { return PollNUT(ctx, n, o, at) }})
	}
	for _, h := range c.SSH {
		if err := h.Validate(); err != nil {
			slog.Warn("hw ssh device skipped", "device", h.Name, "error", err)
			continue
		}
		ts = append(ts, task{"ssh", h.Name, func(ctx context.Context, o sink.Sink, at time.Time) error { return PollSSH(ctx, h, o, at) }})
	}
	for _, a := range c.Arrays {
		ts = append(ts, task{"array", a.Name, func(ctx context.Context, o sink.Sink, at time.Time) error { return PollArray(ctx, a, o, at) }})
	}
	return ts
}

// pollAll runs every task at once, each under its own deadline.
func pollAll(ctx context.Context, ts []task, out sink.Sink, deadline time.Duration) {
	var wg sync.WaitGroup
	for _, t := range ts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, deadline)
			defer cancel()
			done := make(chan error, 1)
			at := time.Now()
			go func() { done <- t.run(dctx, out, at) }()
			select {
			case err := <-done:
				if err != nil {
					slog.Warn("hardware poll failed", "kind", t.kind, "device", t.name, "error", err)
				}
			case <-dctx.Done():
				slog.Warn("hardware poll timed out", "kind", t.kind, "device", t.name)
			}
		}()
	}
	wg.Wait()
}

// Run polls until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("hw config: %w", err)
		}
	}
	ts := c.tasks()
	if c.Enabled != nil && !*c.Enabled || len(ts) == 0 {
		<-ctx.Done()
		return nil
	}
	every := host.Duration(c.Interval, 60*time.Second, 15*time.Second)
	deadline := min(host.Duration(c.PollTimeout, 30*time.Second, time.Second), every)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		pollAll(ctx, ts, out, deadline)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
