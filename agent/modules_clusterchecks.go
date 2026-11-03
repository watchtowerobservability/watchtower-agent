package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/custom"
)

// clusterChecksModule is `cluster_checks` (INF-008, Datadog cluster-check dispatching): checks
// of cluster-level services (a managed database, an external endpoint) are configured on every
// node agent, and each runs on exactly one of them: the rendezvous-hash owner of the check name
// over the live agents (custom.JoinCluster, peers from the agent chart's headless service). When
// that agent leaves, only its checks move. Checks name an integration or prometheus module and
// carry its config; everything is local-file only (remote config may only toggle the module).
type clusterChecksModule struct {
	toggle
	reg Registry
}

type clusterCheck struct {
	Name   string          `json:"name"`
	Module string          `json:"module"`
	Config json.RawMessage `json:"config"`
}

type clusterChecksConfig struct {
	Cluster custom.ClusterConfig `json:"cluster"`
	Checks  []clusterCheck       `json:"checks"`
}

func (clusterChecksModule) Name() string { return "cluster_checks" }

func (m clusterChecksModule) Start(ctx context.Context, raw json.RawMessage, out Exporter) error {
	var c clusterChecksConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	mods, err := m.resolve(c.Checks)
	if err != nil {
		return err
	}
	owns, err := custom.JoinCluster(ctx, c.Cluster, out)
	if err != nil {
		return err
	}
	dispatch(ctx, 15*time.Second, c.Checks, mods, owns, out)
	return nil
}

// resolve checks every check names a module this agent may run on behalf of the cluster.
func (m clusterChecksModule) resolve(cs []clusterCheck) (map[string]Module, error) {
	if len(cs) > 200 {
		return nil, errors.New("cluster_checks: at most 200 checks")
	}
	out := map[string]Module{}
	for _, c := range cs {
		if c.Name == "" || out[c.Name] != nil {
			return nil, fmt.Errorf("cluster_checks: check names must be unique and non-empty (%q)", c.Name)
		}
		mod := m.reg[c.Module]
		switch mod.(type) {
		case integrationModule, promModule, nagiosModule:
		default:
			return nil, fmt.Errorf("cluster_checks: %s: module %q cannot run as a cluster check", c.Name, c.Module)
		}
		out[c.Name] = mod
	}
	return out, nil
}

// dispatch keeps the checks this agent owns running and stops the ones that moved away.
func dispatch(ctx context.Context, every time.Duration, cs []clusterCheck, mods map[string]Module, owns func(string) bool, out Exporter) {
	running := map[string]context.CancelFunc{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for _, c := range cs {
			cancel, on := running[c.Name]
			switch mine := owns(c.Name); {
			case mine && !on:
				cctx, stop := context.WithCancel(ctx)
				running[c.Name] = stop
				go func() {
					// restart on exit (a changed secret, a failed start) until the check moves away
					for cctx.Err() == nil {
						err := withSecrets(cctx, c.Config, func(ctx context.Context, cfg json.RawMessage) error { return mods[c.Name].Start(ctx, cfg, out) })
						if err != nil && cctx.Err() == nil {
							slog.Warn("cluster_checks: check stopped, restarting", "check", c.Name, "error", err)
						}
						select {
						case <-cctx.Done():
						case <-time.After(10 * time.Second):
						}
					}
				}()
			case !mine && on:
				cancel()
				delete(running, c.Name)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
