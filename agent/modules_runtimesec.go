package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/watchtowerobservability/watchtower-agent/agent/runtimesec"
)

// runtimeSecModule is `runtime_security` (D1 Workload Protection): eBPF exec/file/network hooks
// that emit security signals against a default policy. Off unless the local config enables it;
// remote config can only toggle it (the policy names paths and programs, so it stays local).
type runtimeSecModule struct{ toggle }

func (runtimeSecModule) Name() string { return "runtime_security" }

func (runtimeSecModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	host, _ := os.Hostname()
	return runtimesec.Run(ctx, cfg, out, host)
}
