// Package host collects host and process metrics with OTel semantic-convention names, through
// gopsutil (pure Go, no cgo, Linux/Windows/macOS).
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	ghost "github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	defaultInterval        = 10 * time.Second
	minInterval            = time.Second
	defaultProcessInterval = 30 * time.Second
)

// Config is the host module's config. Only Enabled and Interval can be set remotely.
type Config struct {
	Enabled         *bool     `json:"enabled"`
	Interval        string    `json:"interval"`         // default 10s, at least 1s
	ProcessInterval string    `json:"process_interval"` // default 30s, at least 5s
	Processes       *bool     `json:"processes"`        // default true
	Discovery       Discovery `json:"discovery"`
	Emit            string    `json:"emit"` // otel (default), node_exporter or both
}

// ParseConfig decodes and validates cfg (empty means defaults).
func ParseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return c, err
		}
	}
	switch c.Emit {
	case "", EmitOTel, EmitNodeExporter, EmitBoth:
	default:
		return c, fmt.Errorf("host: emit %q must be otel, node_exporter or both", c.Emit)
	}
	return c, c.Discovery.Validate()
}

// Duration parses s, falling back to def and clamping up to floor.
func Duration(s string, def, floor time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return max(d, floor)
}

// Run collects until ctx ends. A disabled module just waits.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c, err := ParseConfig(raw)
	if err != nil {
		return err
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	_, _ = cpu.Percent(0, false) // primes the delta for the first real sample
	every := Duration(c.Interval, defaultInterval, minInterval)
	t := time.NewTicker(every)
	defer t.Stop()
	var procs *Processes
	if c.Processes == nil || *c.Processes {
		procs = NewProcesses(Duration(c.ProcessInterval, defaultProcessInterval, 5*time.Second))
	}
	out = WrapEmit(out, c.Emit)
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-t.C:
			Collect(out, c.Discovery, now)
			procs.Maybe(out, now)
		}
	}
}

// Collect takes one pass of host metrics. A failing source is logged and skipped.
func Collect(out sink.Sink, d Discovery, at time.Time) {
	if p, err := cpu.Percent(0, false); err == nil && len(p) == 1 {
		out.Gauge("system.cpu.utilization", "1", p[0]/100, nil, at)
	}
	if l, err := load.Avg(); err == nil {
		out.Gauge("system.cpu.load_average.1m", "{thread}", l.Load1, nil, at)
		out.Gauge("system.cpu.load_average.5m", "{thread}", l.Load5, nil, at)
		out.Gauge("system.cpu.load_average.15m", "{thread}", l.Load15, nil, at)
	}
	if m, err := mem.VirtualMemory(); err == nil {
		out.Gauge("system.memory.usage", "By", float64(m.Used), map[string]string{"state": "used"}, at)
		out.Gauge("system.memory.usage", "By", float64(m.Available), map[string]string{"state": "free"}, at)
		out.Gauge("system.memory.utilization", "1", m.UsedPercent/100, nil, at)
		out.Gauge("system.memory.limit", "By", float64(m.Total), nil, at)
	}
	if up, err := ghost.Uptime(); err == nil {
		out.Gauge("system.uptime", "s", float64(up), nil, at)
	}
	if parts, err := disk.Partitions(false); err == nil {
		fss := make([]FS, 0, len(parts))
		for _, p := range parts {
			if u, err := disk.Usage(p.Mountpoint); err == nil {
				fss = append(fss, FS{Device: p.Device, Mount: p.Mountpoint, Type: p.Fstype, Used: u.Used, Free: u.Free})
			}
		}
		EmitFilesystems(out, d, fss, at)
	}
	if io, err := disk.IOCounters(); err == nil {
		devs := map[string][2]uint64{}
		for n, c := range io {
			devs[n] = [2]uint64{c.ReadBytes, c.WriteBytes}
		}
		EmitIO(out, d, KindDisk, "system.disk.io", devs, [2]string{"read", "write"}, at)
	}
	if nics, err := gnet.IOCounters(true); err == nil {
		devs := map[string][2]uint64{}
		for _, c := range nics {
			devs[c.Name] = [2]uint64{c.BytesRecv, c.BytesSent}
		}
		EmitIO(out, d, KindNIC, "system.network.io", devs, [2]string{"receive", "transmit"}, at)
	}
}

// FS is one mounted filesystem.
type FS struct {
	Device, Mount, Type string
	Used, Free          uint64
}

// EmitFilesystems writes system.filesystem.usage for each filesystem the discovery rules allow.
// The parent host is not stamped: the worker derives it from the resource host.name.
func EmitFilesystems(out sink.Sink, d Discovery, fss []FS, at time.Time) {
	for _, f := range fss {
		if !d.Allow(KindFilesystem, f.Mount) {
			continue
		}
		base := map[string]string{"device": f.Device, "mountpoint": f.Mount, "type": f.Type}
		out.Gauge("system.filesystem.usage", "By", float64(f.Used), sink.With(base, "state", "used"), at)
		out.Gauge("system.filesystem.usage", "By", float64(f.Free), sink.With(base, "state", "free"), at)
		out.Gauge("system.filesystem.limit", "By", float64(f.Used+f.Free), base, at)
	}
}

// EmitIO writes a cumulative byte counter per device and direction (dirs[0] for vals[0]).
func EmitIO(out sink.Sink, d Discovery, kind, name string, devs map[string][2]uint64, dirs [2]string, at time.Time) {
	for dev, v := range devs {
		if !d.Allow(kind, dev) {
			continue
		}
		base := map[string]string{"device": dev}
		for i, dir := range dirs {
			out.Sum(name, "By", float64(v[i]), sink.With(base, "direction", dir), at)
		}
	}
}
