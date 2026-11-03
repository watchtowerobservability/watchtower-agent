package main

import (
	"context"
	"encoding/json"

	"github.com/watchtowerobservability/watchtower-agent/agent/autoinst"
)

// autoinstModule is `autoinst` (APM-011): host single-step auto-instrumentation, the Linux
// LD_PRELOAD shim for allowlisted executables and IIS application pools on Windows. It acts only
// on targets the local config names; remote config can only toggle it (off removes it again).
type autoinstModule struct{ toggle }

func (autoinstModule) Name() string { return "autoinst" }

func (autoinstModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	return autoinst.Run(ctx, cfg)
}
