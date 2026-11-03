package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/custom"
	"github.com/watchtowerobservability/watchtower-agent/agent/k8s"
)

// autodiscoverModule turns pods annotated watchtower.dev/scrape (found by the k8s_node module)
// and containers labeled the same way into scrapes. A target that also names
// watchtower.dev/integration runs that integration module instead, with the base config the
// agent's own file gives under `integrations.<name>`, where "%%host%%" and "%%port%%" become the
// target's address. Annotations and labels only pick among integrations the operator configured
// and only ever point at the workload's own IP, so a pod editor cannot aim the agent elsewhere
// or pull other credentials into it.
type autodiscoverModule struct {
	toggle
	reg Registry
}

type autodiscoverConfig struct {
	Interval     string                     `json:"interval"` // default 30s
	Docker       bool                       `json:"docker"`   // also read Docker labels
	DockerHost   string                     `json:"docker_host"`
	Integrations map[string]json.RawMessage `json:"integrations"`
}

// adTarget is one discovered endpoint, from either source.
type adTarget struct {
	key, ip, path, integration string
	port                       int
	labels                     map[string]string
}

func (autodiscoverModule) Name() string { return "autodiscovery" }

func (m autodiscoverModule) Start(ctx context.Context, raw json.RawMessage, out Exporter) error {
	var c autodiscoverConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	every := 30 * time.Second
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		if err != nil || d < 5*time.Second {
			return errors.New("autodiscovery interval must be a duration of at least 5s")
		}
		every = d
	}
	var docker *container.Docker
	if c.Docker {
		host := c.DockerHost
		if host == "" {
			host = container.DefaultHost()
		}
		d, err := container.NewDocker(host)
		if err != nil {
			return err
		}
		docker = d
	}
	list := func(ctx context.Context) []adTarget {
		ts := podTargets(k8s.Targets())
		if docker != nil {
			cs, err := docker.List(ctx)
			if err != nil {
				slog.Warn("autodiscovery: docker list failed", "error", err)
			}
			ts = append(ts, labelTargets(container.LabelTargets(cs))...)
		}
		return ts
	}
	go custom.Prometheus{}.Watch(ctx, every, func(ctx context.Context) ([]custom.TargetSpec, error) {
		var specs []custom.TargetSpec
		for _, t := range list(ctx) {
			if t.integration == "" {
				specs = append(specs, custom.TargetSpec{URL: "http://" + net.JoinHostPort(t.ip, strconv.Itoa(t.port)) + t.path, Labels: t.labels})
			}
		}
		return specs, nil
	}, out)
	m.bindIntegrations(ctx, every, c.Integrations, list, out)
	return nil
}

// bindIntegrations keeps one integration module running per discovered integration target.
func (m autodiscoverModule) bindIntegrations(ctx context.Context, every time.Duration, base map[string]json.RawMessage,
	list func(context.Context) []adTarget, out Exporter) {
	running := map[string]context.CancelFunc{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		want := map[string]bool{}
		for _, tg := range list(ctx) {
			if tg.integration == "" {
				continue
			}
			key := tg.key + "|" + tg.integration
			want[key] = true
			if _, ok := running[key]; ok {
				continue
			}
			mod, cfg, err := m.bind(tg, base)
			if err != nil {
				slog.Warn("autodiscovery: integration not bound", "target", tg.key, "integration", tg.integration, "error", err)
				continue
			}
			cctx, cancel := context.WithCancel(ctx)
			running[key] = cancel
			go func() {
				if err := mod.Start(cctx, cfg, out); err != nil && cctx.Err() == nil {
					slog.Warn("autodiscovery: integration stopped", "target", tg.key, "integration", tg.integration, "error", err)
				}
			}()
		}
		for k, cancel := range running {
			if !want[k] {
				cancel()
				delete(running, k)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// bind resolves a target's integration to a module and its config. Only integration modules
// (not hw, logs, snmp, ...) with a base config in the local file can be bound.
func (m autodiscoverModule) bind(t adTarget, base map[string]json.RawMessage) (Module, json.RawMessage, error) {
	mod, ok := m.reg[t.integration].(integrationModule)
	if !ok {
		return nil, nil, errors.New("no integration module of that name")
	}
	b, ok := base[t.integration]
	if !ok {
		return nil, nil, errors.New("autodiscovery.integrations has no base config for it")
	}
	cfg, err := templateConfig(b, t.ip, t.port)
	return mod, cfg, err
}

// templateConfig substitutes %%host%% and %%port%% in the base config. ip is a parsed IP and port
// a number, so the substitution cannot break out of a JSON string.
func templateConfig(base json.RawMessage, ip string, port int) (json.RawMessage, error) {
	s := string(base)
	if !strings.Contains(s, "%%host%%") {
		return nil, errors.New(`the base config must contain "%%host%%"`)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, errors.New("target IP is not an IP")
	}
	host := parsed.String()
	if parsed.To4() == nil {
		host = "[" + host + "]" // host:port forms need brackets for IPv6
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, "%%host%%", host), "%%port%%", strconv.Itoa(port))
	if !json.Valid([]byte(s)) {
		return nil, errors.New("the templated config is not JSON")
	}
	return json.RawMessage(s), nil
}

func podTargets(ts []k8s.Target) []adTarget {
	out := make([]adTarget, 0, len(ts))
	for _, t := range ts {
		out = append(out, adTarget{key: "pod/" + t.Namespace + "/" + t.Pod + ":" + strconv.Itoa(t.Port), ip: t.IP, port: t.Port,
			path: t.Path, integration: t.Integration,
			labels: map[string]string{"k8s.namespace.name": t.Namespace, "k8s.pod.name": t.Pod, "k8s.pod.uid": t.UID}})
	}
	return out
}

func labelTargets(ts []container.LabelTarget) []adTarget {
	out := make([]adTarget, 0, len(ts))
	for _, t := range ts {
		out = append(out, adTarget{key: "container/" + t.ID + ":" + strconv.Itoa(t.Port), ip: t.IP, port: t.Port,
			path: t.Path, integration: t.Integration,
			labels: map[string]string{"container.id": t.ID, "container.name": t.Name}})
	}
	return out
}
