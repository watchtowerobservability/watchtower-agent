// Package netpath runs the uptime `network_path` driver (U2) from the agent, so a path can be
// traced from inside a private network. The tracer lives in icmp.go.
package netpath

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxTargets  = 50
	minInterval = 30 * time.Second
	runTimeout  = 30 * time.Second
)

// Target is one destination to trace.
type Target struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	MaxHops int    `json:"max_hops,omitempty"`
	Probes  int    `json:"probes,omitempty"`
	// Proto "tcp" or "udp" traces with that protocol on Port (default 443 / 33434) instead of
	// ICMP echo; Paths > 1 varies the source port to find equal-cost routes.
	Proto string `json:"proto,omitempty"`
	Port  int    `json:"port,omitempty"`
	Paths int    `json:"paths,omitempty"`
	// Zone names the destination's network zone (path.dst_zone) for the zone matrix.
	Zone string `json:"zone,omitempty"`
}

// Config is the module's own settings.
type Config struct {
	Enabled  *bool    `json:"enabled"`
	Interval string   `json:"interval"`
	Targets  []Target `json:"targets"`
	// Zone names the network zone this agent probes from (path.src_zone), e.g. "eu-west/app".
	Zone string `json:"zone"`
}

// Once traces every target once and writes `wt_path_up`, `wt_path_hops` and one
// `network.path` log record (the hops as JSON) per target.
func Once(ctx context.Context, d Tracer, targets []Target, out sink.Sink, at time.Time) {
	for _, t := range targets {
		if t.Proto == ProtoTCP || t.Proto == ProtoUDP {
			socketOnce(ctx, t, out, at)
			continue
		}
		c, cancel := context.WithTimeout(ctx, runTimeout)
		body, hops, up, errText := d(c, t.Host, t.MaxHops, t.Probes)
		cancel()
		attrs := map[string]string{"path.target": t.Name, "path.host": t.Host}
		out.Gauge("wt_path_up", "", b2f(up), attrs, at)
		out.Gauge("wt_path_hops", "", float64(hops), attrs, at)
		out.Log("INFO", body, map[string]string{
			"event.name": "network.path", "path.target": t.Name, "path.host": t.Host,
			"path.reached": boolStr(up), "path.error": errText,
		}, at)
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Run traces the configured targets every interval (at least 30 s, default 60 s).
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if len(c.Targets) > maxTargets {
		return errors.New("netpath: too many targets")
	}
	for _, t := range c.Targets {
		if !validProto(t.Proto) || t.Port < 0 || t.Port > 65535 || t.Paths < 0 || t.Paths > MaxPaths {
			return errors.New("netpath: bad proto, port or paths")
		}
		if validHost(t.Host) != nil || t.MaxHops < 0 || t.MaxHops > icmpMaxHops || t.Probes < 0 || t.Probes > icmpProbes {
			return errors.New("netpath: bad host, max_hops or probes")
		}
	}
	every := time.Minute
	if c.Interval != "" {
		var err error
		if every, err = time.ParseDuration(c.Interval); err != nil {
			return errors.New("netpath: interval is not a duration")
		}
	}
	every = max(every, minInterval)
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 {
		<-ctx.Done()
		return nil
	}
	out = withZones(out, c.Zone, c.Targets)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		Once(ctx, ICMPTracer, c.Targets, out, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
