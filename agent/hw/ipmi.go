package hw

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// IPMI runs `ipmitool sdr elist` at a locally configured path. With Host set it talks to a BMC
// over the LAN; the password is read by ipmitool from PasswordFile and never appears in the
// argument list.
type IPMI struct {
	Name         string `json:"name"`
	Path         string `json:"path"` // empty or missing: the module is disabled
	Host         string `json:"host"`
	User         string `json:"user"`
	PasswordFile string `json:"password_file"`
	Scope        Scope  `json:"scope"` // what the machine serves; stamped on every sample
}

// SDR is one line of `ipmitool sdr elist`.
type SDR struct {
	Name, ID, Status string
	Value            float64
	HasValue         bool
	Unit             string
}

// ParseSDR parses `ipmitool sdr elist` output: "Name | id | status | entity | reading".
// Lines that are not five fields are ignored.
func ParseSDR(r io.Reader) ([]SDR, error) {
	var out []SDR
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() && len(out) < 5000 {
		f := strings.Split(sc.Text(), "|")
		if len(f) != 5 {
			continue
		}
		s := SDR{Name: strings.TrimSpace(f[0]), ID: strings.TrimSpace(f[1]), Status: strings.ToLower(strings.TrimSpace(f[2]))}
		if rd := strings.Fields(f[4]); len(rd) > 0 {
			if v, err := strconv.ParseFloat(rd[0], 64); err == nil {
				s.Value, s.HasValue, s.Unit = v, true, strings.Join(rd[1:], " ")
			}
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

var ipmiUnits = map[string]struct{ metric, unit, typ string }{
	"degrees c": {"hw.temperature", "Cel", "temperature"}, "rpm": {"hw.fan.speed", "rpm", "fan"}, "volts": {"hw.voltage", "V", "voltage"},
	"watts": {"hw.power", "W", "power_supply"}, "amps": {"hw.current", "A", "power_supply"},
}

// EmitSDR writes the sensor readings and states.
func EmitSDR(out sink.Sink, dev string, rs []SDR, at time.Time) {
	for _, s := range rs {
		a := map[string]string{"hw.ipmi": dev, "hw.id": s.ID + "/" + s.Name, "hw.name": s.Name}
		if m, ok := ipmiUnits[strings.ToLower(s.Unit)]; ok && s.HasValue {
			out.Gauge(m.metric, m.unit, s.Value, sink.With(a, "hw.type", m.typ), at)
		}
		typ := "enclosure" // sensors with no known unit are reported against the enclosure
		if m, ok := ipmiUnits[strings.ToLower(s.Unit)]; ok {
			typ = m.typ
		}
		state := ""
		switch s.Status {
		case "ok":
			state = "ok"
		case "nc":
			state = "degraded"
		case "cr", "nr":
			state = "failed"
		}
		if state != "" { // "ns" (no reading) says nothing about health
			emitState(out, a, typ, state, at)
		}
	}
}

// Available reports whether the configured ipmitool exists.
func (i IPMI) Available() bool {
	if i.Path == "" {
		return false
	}
	st, err := os.Stat(i.Path)
	return err == nil && !st.IsDir()
}

// PollIPMI runs ipmitool with a fixed argument list (no shell) and a 20 s deadline.
func PollIPMI(ctx context.Context, i IPMI, out sink.Sink, at time.Time) error {
	out = withScope(out, i.Scope)
	args := []string{"sdr", "elist"}
	if i.Host != "" {
		args = append([]string{"-I", "lanplus", "-H", i.Host, "-U", i.User, "-f", i.PasswordFile}, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, i.Path, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return errors.New("ipmitool exited with an error") // stderr may name the host or user
		}
		return errors.New("ipmitool could not be run")
	}
	rs, err := ParseSDR(&buf)
	if err != nil {
		return err
	}
	EmitSDR(out, i.Name, rs, at)
	return nil
}
