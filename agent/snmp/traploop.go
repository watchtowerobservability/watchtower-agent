package snmp

import (
	"context"
	"log/slog"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// trapRetry is how long to wait before binding the trap socket again (a variable for tests).
var trapRetry = 5 * time.Minute

const trapUp = "wt.agent.snmp.trap_listener_up"

// trapLoop runs the trap receiver for as long as ctx lives. A failed bind is logged once, shows
// as trap_listener_up = 0 and is retried every trapRetry; it never affects polling.
func trapLoop(ctx context.Context, cfg TrapConfig, out sink.Sink) {
	logged := false
	for ctx.Err() == nil {
		ln, err := NewListener(cfg, out)
		if err == nil {
			err = ln.Listen()
		}
		if err != nil {
			if !logged {
				slog.Warn("snmp trap listener is not running; polling continues", "retry", trapRetry.String(), "error", err)
				logged = true
			}
			out.Gauge(trapUp, "1", 0, nil, time.Now())
			if !sleep(ctx, trapRetry) {
				return
			}
			continue
		}
		logged = false
		served := make(chan error, 1)
		go func() { served <- ln.Serve(ctx) }()
		tk := time.NewTicker(time.Minute)
		running, drained := true, false
		for running {
			out.Gauge(trapUp, "1", 1, nil, time.Now())
			ln.Report(time.Now())
			select {
			case <-ctx.Done():
				running = false
			case err := <-served:
				slog.Warn("snmp trap listener stopped; will rebind", "error", err)
				out.Gauge(trapUp, "1", 0, nil, time.Now())
				running, drained = false, true
			case <-tk.C:
			}
		}
		tk.Stop()
		if ctx.Err() != nil {
			if !drained {
				<-served
			}
			return
		}
		if !sleep(ctx, trapRetry) {
			return
		}
	}
}

// sleep waits d; false means ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
