//go:build !linux

package runtimesec

import (
	"context"
	"fmt"
	"time"
)

// loadAndRun is the non-Linux no-op: the eBPF probes are Linux-only, so the module reports it is
// active-but-inert and waits for shutdown. It never emits. Keeping the signature identical to the
// Linux build lets runtimesec.go stay platform-agnostic.
func loadAndRun(ctx context.Context, _ Config, pol Policy, _ *Emitter, out Sink, host string) error {
	out.Log("info", fmt.Sprintf("runtime_security loaded %d policy rules; eBPF probes are Linux-only, so no events on this platform", len(pol.Rules)),
		map[string]string{"agent.module": "runtime_security", "host.name": host}, time.Now())
	<-ctx.Done()
	return nil
}
