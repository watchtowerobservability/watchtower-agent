package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/custom"
	"github.com/watchtowerobservability/watchtower-agent/agent/integrations"
)

// Module is one collector. Start blocks until ctx ends (or returns an error, after which the
// supervisor restarts it with backoff). cfg is the module's own JSON config.
type Module interface {
	Name() string
	Start(ctx context.Context, cfg json.RawMessage, out Exporter) error
}

// Overlayer is implemented by the modules that remote config may touch. Overlay merges a
// server-sent config into the local one and must refuse anything that could name a program,
// path, argument or URL outside the local policy. A module without it cannot be configured
// remotely at all.
type Overlayer interface {
	Overlay(local, remote json.RawMessage) (json.RawMessage, error)
}

// Registry maps module names to implementations.
type Registry map[string]Module

// NewRegistry returns the built-in modules, configured by the local policy.
func NewRegistry(local *LocalConfig) Registry {
	r := Registry{}
	for _, m := range []Module{
		aiServingModule{},
		selfModule{},
		awsModule{},
		azureEventHubModule{},
		cloudPullModule{},
		containerModule{},
		ebpfModule{local: local},
		dogstatsdModule{},
		ebpfNetModule{},
		ebpfTraceModule{},
		flowsModule{},
		gpuModule{},
		hostModule{toggle{emptyOK: true}},
		integrationModule{name: "activemq", run: integrations.ActiveMQ},
		integrationModule{name: "cassandra", run: integrations.Cassandra},
		integrationModule{name: "ceph", run: integrations.Ceph},
		integrationModule{name: "consul", run: integrations.Consul},
		integrationModule{name: "docker", run: integrations.Docker},
		integrationModule{name: "hyperv", run: integrations.HyperV},
		integrationModule{name: "jmx", run: integrations.JMX},
		integrationModule{name: "kinesis", run: integrations.Kinesis},
		integrationModule{name: "mssql", run: integrations.MSSQL},
		integrationModule{name: "oracle", run: integrations.Oracle},
		integrationModule{name: "pulsar", run: integrations.Pulsar},
		integrationModule{name: "vault", run: integrations.Vault},
		integrationModule{name: "windows", run: integrations.Windows},
		integrationModule{name: "http_status", run: integrations.HTTPStatus},
		hwModule{},
		k8sClusterModule{},
		k8sNodeModule{stateDir: local.StateDir},
		integrationModule{name: "kafka", run: integrations.Kafka},
		integrationModule{name: "listen", run: integrations.Listen},
		logsModule{stateDir: local.StateDir},
		integrationModule{name: "memcached", run: integrations.Memcached},
		integrationModule{name: "mongodb", run: integrations.MongoDB},
		integrationModule{name: "mysql", run: integrations.MySQL},
		netconfModule{},
		nagiosModule{custom.Nagios{PluginDir: local.PluginDir}},
		integrationModule{name: "nats", run: integrations.NATS},
		pathModule{},
		integrationModule{name: "postgres", run: integrations.Postgres},
		promModule{custom.Prometheus{Allow: local.ScrapeAllow}},
		nutanixModule{},
		openstackModule{},
		libvirtModule{},
		proxmoxModule{},
		vsphereModule{},
		integrationModule{name: "rabbitmq", run: integrations.RabbitMQ},
		integrationModule{name: "redis", run: integrations.Redis},
		snmpModule{},
		topologyModule{},
	} {
		r[m.Name()] = m
	}
	return r
}

type selfModule struct{}

func (selfModule) Name() string { return "agent" }

// Start emits `wt_agent_info` (value 1) every 60 s, so a silent agent is visible and the
// export path is proven.
func (selfModule) Start(ctx context.Context, _ json.RawMessage, out Exporter) error {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		out.Gauge("wt_agent_info", "", 1, map[string]string{"version": Version}, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

type nagiosModule struct{ n custom.Nagios }

func (nagiosModule) Name() string { return "nagios" }
func (m nagiosModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return m.n.Run(ctx, cfg, out)
}
func (m nagiosModule) Overlay(l, r json.RawMessage) (json.RawMessage, error) {
	return m.n.Overlay(l, r)
}

// dogstatsdModule has no Overlay: the listen address is local-file only.
type dogstatsdModule struct{}

func (dogstatsdModule) Name() string { return "dogstatsd" }
func (dogstatsdModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return (&custom.DogStatsD{}).Run(ctx, cfg, out)
}

type promModule struct{ p custom.Prometheus }

func (promModule) Name() string { return "prometheus" }
func (m promModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return m.p.Run(ctx, cfg, out)
}
func (m promModule) Overlay(l, r json.RawMessage) (json.RawMessage, error) {
	return m.p.Overlay(l, r)
}

// Plan is the module configs that should run, by name.
type Plan map[string]json.RawMessage

// Merge overlays remote module configs on the local ones through each module's Overlay. A remote
// config for a module that has no Overlay, that the agent does not have, or that Overlay refuses
// is skipped (and reported), never run; the local config of that module stays in force.
func Merge(reg Registry, local map[string]json.RawMessage, remote *RemoteConfig, warn func(string)) Plan {
	// host metrics run by default; a local "host" entry replaces the default config.
	p := Plan{"agent": json.RawMessage(`{}`), "host": json.RawMessage(`{}`)}
	for k, v := range local {
		p[k] = v
	}
	if remote == nil {
		return p
	}
	names := make([]string, 0, len(remote.Modules))
	for k := range remote.Modules {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		m, ok := reg[name]
		if !ok {
			warn(fmt.Sprintf("remote config names unknown module %q: skipped", name))
			continue
		}
		o, ok := m.(Overlayer)
		if !ok {
			warn(fmt.Sprintf("module %q cannot be configured remotely: skipped", name))
			continue
		}
		merged, err := o.Overlay(local[name], remote.Modules[name])
		if err != nil {
			warn(fmt.Sprintf("remote config for module %q refused: %v", name, err))
			continue
		}
		p[name] = merged
	}
	return p
}

// Supervisor runs the planned modules and swaps them when the plan changes.
type Supervisor struct {
	Reg Registry
	Out Exporter

	mu      sync.Mutex
	running map[string]*runner
}

type runner struct {
	cfg    json.RawMessage
	cancel context.CancelFunc
	done   chan struct{}
}

// Apply starts new or changed modules and stops removed ones. Unchanged ones keep running.
func (s *Supervisor) Apply(ctx context.Context, plan Plan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == nil {
		s.running = map[string]*runner{}
	}
	for name, r := range s.running {
		if cfg, ok := plan[name]; !ok || !bytes.Equal(cfg, r.cfg) {
			r.cancel()
			<-r.done
			delete(s.running, name)
		}
	}
	for name, cfg := range plan {
		m, ok := s.Reg[name]
		if !ok || s.running[name] != nil {
			continue
		}
		mctx, cancel := context.WithCancel(ctx)
		r := &runner{cfg: cfg, cancel: cancel, done: make(chan struct{})}
		s.running[name] = r
		go func() {
			defer close(r.done)
			superviseOne(mctx, m, cfg, s.Out)
		}()
	}
}

// Names lists running modules, sorted.
func (s *Supervisor) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n []string
	for k := range s.running {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Stop stops everything.
func (s *Supervisor) Stop() { s.Apply(context.Background(), Plan{}) }

func superviseOne(ctx context.Context, m Module, cfg json.RawMessage, out Exporter) {
	wait := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := m.Start(ctx, cfg, out)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("module stopped, restarting", "module", m.Name(), "error", err)
		if time.Since(started) > time.Minute {
			wait = time.Second
		}
		sleep(ctx, wait)
		wait = min(wait*2, 5*time.Minute)
	}
}
