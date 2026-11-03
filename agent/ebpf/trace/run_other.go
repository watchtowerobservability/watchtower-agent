//go:build !linux

package trace

import (
	"context"
	"encoding/json"
)

// Run waits when the module is disabled and returns ErrUnsupported when it is enabled.
func Run(ctx context.Context, raw json.RawMessage, _ Sink, _ Stats, _ Metric) error {
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
