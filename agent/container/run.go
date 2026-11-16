package container

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
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
	// Labels limit the engine's containers and events to those carrying every label, each with one of its values (a string or a list; sent as a
	// server-side filter). Set, they also turn the cgroup scan off: it cannot see labels.
	Labels LabelSet `json:"labels"`
	// RequireLabels makes empty Labels collect nothing instead of every container (shared hosts).
	RequireLabels bool `json:"require_labels"`
	// Scope "self" (or WT_AGENT_SCOPE=self) sets Labels to the compose project of the agent's own
	// container, read by inspecting only that container. Unresolvable: nothing is collected.
	Scope string `json:"scope"`
	// Services maps a compose service name to the service, environment and version its
	// containers report when they carry no label or OTEL env of their own. Local file only.
	Services map[string]ServiceMap `json:"services"`
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
	if p := os.Getenv("WT_AGENT_DOCKER_PROJECT"); p != "" { // shorthand for the compose project label
		if c.Labels == nil {
			c.Labels = LabelSet{}
		}
		c.Labels[ComposeProjectLabel] = []string{p}
	}
	if c.DockerHost == "" {
		c.DockerHost = DefaultHost()
	}
	out = sink.Hoist(out)
	d, err := NewDocker(c.DockerHost)
	if err != nil {
		return err
	}
	if err := ApplyScope(ctx, "container", c.Scope, &c.Labels, d.Get(ctx)); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if c.RequireLabels && len(c.Labels) == 0 {
		slog.Warn("container: require_labels is set but labels are empty; collecting nothing")
		<-ctx.Done()
		return nil
	}
	if len(c.Labels) > 0 {
		c.CgroupRoot = "off"
	}
	if c.CgroupRoot == "" && runtime.GOOS == "linux" {
		c.CgroupRoot = cgroupRootDefault()
	}
	d.Labels = c.Labels
	if c.Events == nil || *c.Events {
		go followEvents(ctx, d, out)
	}
	p := &Poller{Services: c.Services}
	t := time.NewTicker(host.Duration(c.Interval, 30*time.Second, 5*time.Second))
	defer t.Stop()
	lastMatched := "\x00"
	warnedProjects := len(c.Labels) > 0
	for {
		known := map[string]bool{}
		list, err := p.Collect(ctx, d, out)
		if err != nil {
			slog.Debug("docker engine unavailable", "error", err)
		}
		for _, i := range list {
			known[i.ID] = true
		}
		if !warnedProjects && ProjectsIn(list) > 1 {
			warnedProjects = true
			slog.Warn("container: the engine socket shows containers of several compose projects and no scope or labels are set, so all of them are reported; set container.scope: self (and logs.docker.scope: self) to report only this agent's own compose project")
		}
		if m := MatchedSummary(list); m != lastMatched {
			lastMatched = m
			slog.Info("container: matched containers", "filter", LabelFilter(c.Labels), "count", len(list), "containers", m)
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

// cgroupRootDefault is WT_AGENT_CGROUP_ROOT (a read-only /sys/fs/cgroup mount in a container), else /sys/fs/cgroup.
func cgroupRootDefault() string {
	if r := os.Getenv("WT_AGENT_CGROUP_ROOT"); r != "" {
		return r
	}
	return DefaultCgroupRoot
}

// CgroupsAvailable is true when no Docker socket exists but the cgroup root is readable: the
// agent then starts the cgroups module on its own.
func CgroupsAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return false
	}
	_, err := os.ReadDir(cgroupRootDefault())
	return err == nil
}

// CgroupsConfig is the `cgroups` module's config; the root is local-file only.
type CgroupsConfig struct {
	Enabled    *bool  `json:"enabled"`
	Interval   string `json:"interval"`    // default 30s, at least 5s
	CgroupRoot string `json:"cgroup_root"` // default WT_AGENT_CGROUP_ROOT or /sys/fs/cgroup
	// Parent keeps only cgroups under this slice or path (compose `cgroup_parent`); env WT_AGENT_CGROUP_PARENT.
	Parent string `json:"parent"`
	// Include/Exclude are glob patterns on the cgroup path (and container name when known); see CgroupFilter.
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
	// Scope "self" (with the engine socket mounted) keeps only containers of the agent's own compose project.
	Scope string `json:"scope"`
	// Labels keeps only containers whose log-driver labels (logs.forward) match, like container.labels.
	Labels LabelSet `json:"labels"`
	// NamesFrom "off" stops naming and labelling containers from forwarded log records (default: used).
	NamesFrom string `json:"names_from"`
	// Health are extra probe targets; containers are also probed through their wt.health label.
	Health []HealthConfig `json:"health"`
}

// RunCgroups reports containers from a (read-only) cgroup v2 mount, with no Docker socket.
func RunCgroups(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c CgroupsConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	if c.CgroupRoot == "" {
		c.CgroupRoot = cgroupRootDefault()
	}
	if c.Parent == "" {
		c.Parent = os.Getenv("WT_AGENT_CGROUP_PARENT")
	}
	out = sink.Hoist(out)
	static, err := StaticHealth(c.Health)
	if err != nil {
		return err
	}
	p := &Poller{Filter: &CgroupFilter{Parent: c.Parent, Include: c.Include, Exclude: c.Exclude, Labels: c.Labels},
		NoLearned: c.NamesFrom == "off", StaticHealth: static}
	var d *Docker
	var labels LabelSet
	if self, err := WantsSelf(c.Scope); err != nil {
		return err
	} else if self {
		var err error
		if d, err = NewDocker(DefaultHost()); err != nil {
			return err
		}
		if err = ApplyScope(ctx, "cgroups", c.Scope, &labels, d.Get(ctx)); err != nil {
			return nil // ctx ended
		}
		d.Labels = labels
	}
	t := time.NewTicker(host.Duration(c.Interval, 30*time.Second, 5*time.Second))
	defer t.Stop()
	for {
		if d != nil { // only the ids the engine lists under the scope; an engine error reports nothing
			p.Filter.IDs = map[string]bool{}
			if list, err := d.List(ctx); err != nil {
				slog.Warn("cgroups: scope self: engine unavailable, reporting nothing", "error", err)
			} else {
				for _, i := range list {
					p.Filter.IDs[i.ID] = true
				}
			}
		}
		known := map[string]bool{}
		p.CollectCgroups(c.CgroupRoot, known, out)
		p.ProbeLearned(ctx, out, known)
		p.Prune(known)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
