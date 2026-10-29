//go:build !linux

package net

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrUnsupported is returned by Run on platforms without eBPF support.
var ErrUnsupported = errors.New("ebpf_net: unsupported on this platform (Linux only)")

// Run waits when the module is disabled and returns ErrUnsupported when it is enabled.
func Run(ctx context.Context, raw json.RawMessage, _ Exporter) error {
	cfg, err := ParseConfig(raw)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		<-ctx.Done()
		return nil
	}
	return ErrUnsupported
}
