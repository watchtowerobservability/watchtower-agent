package integrations

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// SystemdConfig is the systemd module config. Units limits the report to these unit names (globs
// allowed, e.g. "nginx.service", "postgresql@*.service"); empty reports every service unit.
type SystemdConfig struct {
	Base
	Units []string `json:"units"`
}

func (c *SystemdConfig) check() error {
	for _, u := range c.Units {
		if _, err := path.Match(u, ""); err != nil {
			return errors.New("units: bad glob " + u)
		}
	}
	return nil
}

// systemctlList is a variable so tests can feed a recorded listing.
var systemctlList = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager").Output()
}

const maxUnits = 500

// Systemd reports `systemd.unit.active` (1 while active, with active_state and sub_state) per
// service unit and `systemd.units.failed` from `systemctl list-units`.
func Systemd(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &SystemdConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "systemd", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		b, err := systemctlList(ctx)
		if err != nil {
			return errors.New("systemctl list-units failed")
		}
		emitSystemd(out, string(b), c.Units, now)
		return nil
	})
}

// emitSystemd parses `UNIT LOAD ACTIVE SUB DESCRIPTION...` lines.
func emitSystemd(out sink.Sink, listing string, units []string, now time.Time) {
	failed, n := 0, 0
	sc := bufio.NewScanner(strings.NewReader(listing))
	for sc.Scan() {
		f := strings.Fields(strings.TrimLeft(sc.Text(), "●* "))
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		if f[2] == "failed" {
			failed++
		}
		if !matchUnit(units, f[0]) || n >= maxUnits {
			continue
		}
		n++
		up := 0.0
		if f[2] == "active" {
			up = 1
		}
		out.Gauge("systemd.unit.active", "1", up, map[string]string{"unit": f[0], "active_state": f[2], "sub_state": f[3]}, now)
	}
	out.Gauge("systemd.units.failed", "{units}", float64(failed), nil, now)
}

func matchUnit(units []string, name string) bool {
	if len(units) == 0 {
		return true
	}
	for _, u := range units {
		if ok, _ := path.Match(u, name); ok {
			return true
		}
	}
	return false
}
