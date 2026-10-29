//go:build !windows

package logs

import (
	"context"
	"log/slog"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// RunWinEvents has nothing to read off Windows.
func RunWinEvents(ctx context.Context, _ WinEvent, _ sink.Sink) error {
	slog.Warn("windows_events is only available on Windows")
	<-ctx.Done()
	return nil
}
