package hw

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// NUT is one Network UPS Tools server (TCP 3493, `LIST VAR`). Local file only.
type NUT struct {
	Name    string `json:"name"`    // shown as hw.ups
	Address string `json:"address"` // host or host:port (default port 3493)
	UPS     string `json:"ups"`     // the UPS name on that server
}

var nutName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// ParseListVar parses the reply to `LIST VAR <ups>` into variable -> value.
func ParseListVar(r io.Reader, ups string) (map[string]string, error) {
	vars := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() && len(vars) < 2000 {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ERR "):
			return nil, fmt.Errorf("nut: %s", strings.TrimPrefix(line, "ERR "))
		case strings.HasPrefix(line, "END LIST VAR"):
			return vars, nil
		case strings.HasPrefix(line, "VAR "+ups+" "):
			p := strings.SplitN(line, " ", 4)
			if len(p) != 4 {
				continue
			}
			v := strings.TrimSpace(p[3])
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(v[1 : len(v)-1])
			}
			vars[p[2]] = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("nut: reply ended before END LIST VAR")
}

var nutNumeric = []struct {
	v, metric, unit string
	scale           float64
	attrs           []string
}{
	{"battery.charge", "hw.battery.charge", "1", 0.01, nil},
	{"battery.runtime", "hw.battery.time_left", "s", 1, nil},
	{"battery.voltage", "hw.battery.voltage", "V", 1, nil},
	{"battery.temperature", "hw.battery.temperature", "Cel", 1, nil},
	{"ups.load", "hw.ups.output.load", "1", 0.01, nil},
	{"ups.realpower", "hw.power", "W", 1, []string{"hw.power.direction", "output"}},
	{"ups.temperature", "hw.temperature", "Cel", 1, nil},
	{"input.voltage", "hw.ups.input.voltage", "V", 1, nil},
	{"output.voltage", "hw.ups.output.voltage", "V", 1, nil},
}

// EmitNUT writes hw.battery.* and hw.power metrics from the variables.
func EmitNUT(out sink.Sink, n NUT, vars map[string]string, at time.Time) {
	a := map[string]string{"hw.ups": n.Name, "hw.id": n.UPS}
	for _, m := range nutNumeric {
		if f, err := strconv.ParseFloat(vars[m.v], 64); err == nil {
			out.Gauge(m.metric, m.unit, f*m.scale, sink.With(a, m.attrs...), at)
		}
	}
	if st, ok := vars["ups.status"]; ok {
		flags := map[string]bool{}
		for _, t := range strings.Fields(st) {
			flags[t] = true
		}
		b := func(on bool) float64 {
			if on {
				return 1
			}
			return 0
		}
		out.Gauge("hw.ups.on_battery", "1", b(flags["OB"]), a, at)
		out.Gauge("hw.battery.low", "1", b(flags["LB"]), a, at)
		out.Gauge("hw.battery.replace", "1", b(flags["RB"]), a, at)
		out.Gauge("hw.ups.overload", "1", b(flags["OVER"]), a, at)
	}
}

// PollNUT asks one server for the UPS's variables (5 s to connect, 10 s in all).
func PollNUT(ctx context.Context, n NUT, out sink.Sink, at time.Time) error {
	if !nutName.MatchString(n.UPS) {
		return errors.New("nut: ups name has characters outside A-Za-z0-9._@-")
	}
	addr := n.Address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "3493")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return errors.New("nut: cannot connect") // the error text would carry the address
	}
	defer conn.Close()
	dl := time.Now().Add(10 * time.Second)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = conn.SetDeadline(dl)
	if _, err := io.WriteString(conn, "LIST VAR "+n.UPS+"\n"); err != nil {
		return errors.New("nut: write failed")
	}
	vars, err := ParseListVar(conn, n.UPS)
	if err != nil {
		return err
	}
	EmitNUT(out, n, vars, at)
	return nil
}
