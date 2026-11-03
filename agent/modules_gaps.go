package main

import (
	"context"
	"encoding/json"

	"github.com/watchtowerobservability/watchtower-agent/agent/discovery"
	"github.com/watchtowerobservability/watchtower-agent/agent/gnmi"
)

// gnmiModule is `gnmi` (INF-016): gNMI streaming telemetry subscriptions. Targets, paths and
// credential files exist only in the agent's own file; remote config can only toggle it.
type gnmiModule struct{ toggle }

func (gnmiModule) Name() string { return "gnmi" }
func (gnmiModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return gnmi.Run(ctx, cfg, out)
}

// discoveryModule is `discovery` (INF-021): the opt-in subnet scan. Subnets and communities
// exist only in the agent's own file; remote config can only toggle it and set the interval.
type discoveryModule struct{ toggle }

func (discoveryModule) Name() string { return "discovery" }
func (discoveryModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return discovery.Run(ctx, cfg, out)
}
