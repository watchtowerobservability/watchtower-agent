package main

import (
	"context"
	"encoding/json"

	"github.com/watchtowerobservability/watchtower-agent/agent/rulesync"
)

// ruleSyncModule is `prometheus_rules` (CFT-A09): PrometheusRule CRDs kept in sync as rule
// groups. Off unless the local config enables it; remote config can only toggle it.
type ruleSyncModule struct{ toggle }

func (ruleSyncModule) Name() string { return "prometheus_rules" }

func (ruleSyncModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	return rulesync.Run(ctx, cfg)
}

// lldRulesModule is `lld_rules` (INF-020): alert-rule prototypes instantiated per discovered
// filesystem, disk and interface. Local config only (it holds the API key); remote may toggle it.
type lldRulesModule struct{ toggle }

func (lldRulesModule) Name() string { return "lld_rules" }

func (lldRulesModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	return rulesync.RunLLD(ctx, cfg)
}
