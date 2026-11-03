package main

import (
	"context"
	"encoding/json"

	"github.com/watchtowerobservability/watchtower-agent/agent/runtime"
)

// runtimeModule is `runtime_metrics` (CFT-E10): JVM metrics from hsperfdata, no SDK or attach.
// Off unless the local config enables it; remote config can only toggle it.
type runtimeModule struct{ toggle }

func (runtimeModule) Name() string { return "runtime_metrics" }

func (runtimeModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return runtime.Run(ctx, cfg, out)
}
