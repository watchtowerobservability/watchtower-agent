package container

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Config is the container module's config. Only Enabled and Interval can be set remotely;
// DockerHost and CgroupRoot are local-file only.
type Config struct {
	Enabled    *bool  `json:"enabled"`
	Interval   string `json:"interval"`    // default 30s, at least 5s
	DockerHost string `json:"docker_host"` // default: the platform's engine socket
	CgroupRoot string `json:"cgroup_root"` // default /sys/fs/cgroup on Linux; "off" disables
	Events     *bool  `json:"events"`      // default true
}

// Run polls until ctx ends. A missing engine is not an error: the module keeps trying and the
// cgroup scan still reports.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	if c.DockerHost == "" {
		c.DockerHost = DefaultHost()
	}
	if c.CgroupRoot == "" && runtime.GOOS == "linux" {
		c.CgroupRoot = DefaultCgroupRoot
	}
	out = sink.Hoist(out)
	d, err := NewDocker(c.DockerHost)
	if err != nil {
		return err
	}
	if c.Events == nil || *c.Events {
		go followEvents(ctx, d, out)
	}
	p := &Poller{}
	t := time.NewTicker(host.Duration(c.Interval, 30*time.Second, 5*time.Second))
	defer t.Stop()
	for {
		known := map[string]bool{}
		list, err := p.Collect(ctx, d, out)
		if err != nil {
			slog.Debug("docker engine unavailable", "error", err)
		}
		for _, i := range list {
			known[i.ID] = true
		}
		if c.CgroupRoot != "" && c.CgroupRoot != "off" {
			p.CollectCgroups(c.CgroupRoot, known, out)
		}
		p.Prune(known)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func followEvents(ctx context.Context, d *Docker, out sink.Sink) {
	since := time.Now()
	for ctx.Err() == nil {
		if err := d.Events(ctx, since, out); err != nil && ctx.Err() == nil {
			slog.Debug("docker events", "error", err)
		}
		since = time.Now().Add(-time.Second)
		select {
		case <-ctx.Done():
		case <-time.After(15 * time.Second):
		}
	}
}
