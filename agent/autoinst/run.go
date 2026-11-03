package autoinst

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// Run applies the config, re-applies it every interval (default 5m; a no-op unless something
// drifted) and, when the module is toggled off, removes what an earlier run installed.
func Run(ctx context.Context, raw json.RawMessage) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if !c.Enabled {
		if err := remove(c); err != nil {
			slog.Warn("autoinst: remove failed", "error", err)
		}
		<-ctx.Done()
		return nil
	}
	if err := c.Validate(); err != nil {
		return err
	}
	every, err := time.ParseDuration(c.Interval)
	if err != nil || every < time.Minute {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := apply(c); err != nil {
			return err // the supervisor restarts the module with backoff and reports the error
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
