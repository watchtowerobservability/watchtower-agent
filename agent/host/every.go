package host

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Every calls fn now and then every interval until ctx ends.
func Every(ctx context.Context, interval time.Duration, fn func(ctx context.Context)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Redact returns err with every non-empty secret replaced, so a credential a library echoes in
// an error never reaches a log, a label or the wire.
func Redact(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return errors.New(msg)
}

var (
	warnMu   sync.Mutex
	warnLast = map[string]time.Time{}
)

// Warn logs err for key at most once per 10 minutes, so a persistent failure (bad credentials,
// unreachable target) is visible without flooding the log. err must already be redacted.
func Warn(key string, err error) {
	if err == nil {
		return
	}
	warnMu.Lock()
	defer warnMu.Unlock()
	if t, ok := warnLast[key]; ok && time.Since(t) < 10*time.Minute {
		return
	}
	warnLast[key] = time.Now()
	slog.Warn("collector error", "source", key, "err", err)
}
