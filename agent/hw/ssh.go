package hw

// SSH hardware checks (INF-011): disk SMART, NVMe health and Linux software RAID read over SSH
// from servers that have no BMC. The agent runs a fixed set of commands (smartctl, nvme,
// cat /proc/mdstat) on device paths from its own file; nothing the server sends can change them.
// The host key must be pinned: without one the agent connects once, logs the fingerprint the
// server presented and runs nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/netconf"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxSSHOutput = 1 << 20
	maxSSHDisks  = 64
)

// SSHHost is one server read over SSH. Secrets live in files named here, never in the JSON.
type SSHHost struct {
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	Port           int      `json:"port"` // default 22
	User           string   `json:"user"`
	PasswordFile   string   `json:"password_file"`
	PrivateKeyFile string   `json:"private_key_file"`
	HostKey        string   `json:"host_key"` // pinned "SHA256:..." fingerprint; required
	Sudo           bool     `json:"sudo"`     // run the tools through `sudo -n`
	Disks          []string `json:"disks"`    // smartctl devices, e.g. /dev/sda
	NVMe           []string `json:"nvme"`     // nvme devices, e.g. /dev/nvme0
	MDStat         *bool    `json:"mdstat"`   // read /proc/mdstat; default true
	Scope          Scope    `json:"scope"`
}

var devPath = regexp.MustCompile(`^/dev/[A-Za-z0-9_/-]{1,64}$`)

// Validate refuses device paths that are not plain /dev entries, so no shell text gets in.
func (h SSHHost) Validate() error {
	if h.Name == "" || h.Host == "" || h.User == "" {
		return errors.New("hw ssh: name, host and user are required")
	}
	if len(h.Disks)+len(h.NVMe) > maxSSHDisks {
		return fmt.Errorf("hw ssh %q: at most %d devices", h.Name, maxSSHDisks)
	}
	for _, d := range append(append([]string(nil), h.Disks...), h.NVMe...) {
		if !devPath.MatchString(d) || strings.Contains(d, "..") {
			return fmt.Errorf("hw ssh %q: %q is not a /dev path", h.Name, d)
		}
	}
	return nil
}

func (h SSHHost) device() (netconf.Device, error) {
	d := netconf.Device{ID: h.Name, Host: h.Host, Port: h.Port, HostKey: h.HostKey, Username: h.User}
	if d.Port == 0 {
		d.Port = 22
	}
	if h.PasswordFile != "" {
		b, err := os.ReadFile(h.PasswordFile)
		if err != nil {
			return d, errors.New("hw ssh: password_file cannot be read")
		}
		d.Password = strings.TrimRight(string(b), "\r\n")
	}
	if h.PrivateKeyFile != "" {
		b, err := os.ReadFile(h.PrivateKeyFile)
		if err != nil {
			return d, errors.New("hw ssh: private_key_file cannot be read")
		}
		d.PrivateKey = string(b)
	}
	return d, nil
}

func (h SSHHost) cmd(tool string, args ...string) string {
	c := tool + " " + strings.Join(args, " ")
	if h.Sudo {
		return "sudo -n " + c
	}
	return c
}

// PollSSH connects, runs the configured checks and emits what they report.
func PollSSH(ctx context.Context, h SSHHost, out sink.Sink, at time.Time) error {
	out = withScope(out, h.Scope)
	base := map[string]string{"hw.ssh": h.Name}
	if err := h.Validate(); err != nil {
		return err
	}
	d, err := h.device()
	if err != nil {
		return err
	}
	s, err := netconf.Dial(ctx, d)
	if err != nil {
		out.Gauge("hw.ssh.up", "1", 0, base, at)
		if errors.Is(err, netconf.ErrHostKeyChanged) {
			return errors.New("hw ssh: host key does not match the pinned key")
		}
		return errors.New("hw ssh: connection failed")
	}
	defer s.Close()
	if h.HostKey == "" {
		slog.Warn("hw ssh: no host_key pinned, nothing run; pin the presented key", "device", h.Name, "host_key", s.Fingerprint)
		out.Gauge("hw.ssh.up", "1", 0, base, at)
		return nil
	}
	out.Gauge("hw.ssh.up", "1", 1, base, at)
	var first error
	for _, dev := range h.Disks {
		b, err := s.Output(h.cmd("smartctl", "-j", "-H", "-A", "-i", dev), maxSSHOutput)
		if err == nil {
			err = EmitSmart(out, base, dev, b, at)
		}
		first = cmpErr(first, err)
	}
	for _, dev := range h.NVMe {
		b, err := s.Output(h.cmd("nvme", "smart-log", "-o", "json", dev), maxSSHOutput)
		if err == nil {
			err = EmitNVMe(out, base, dev, b, at)
		}
		first = cmpErr(first, err)
	}
	if h.MDStat == nil || *h.MDStat {
		b, err := s.Output("cat /proc/mdstat", maxSSHOutput)
		if err == nil {
			EmitMDStat(out, base, ParseMDStat(string(b)), at)
		}
		first = cmpErr(first, err)
	}
	return first
}

func cmpErr(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

type smartReport struct {
	Device struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"device"`
	Model       string `json:"model_name"`
	Serial      string `json:"serial_number"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current float64 `json:"current"`
	} `json:"temperature"`
	PowerOn *struct {
		Hours float64 `json:"hours"`
	} `json:"power_on_time"`
	ATA *struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value float64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe *nvmeLog `json:"nvme_smart_health_information_log"`
}

// ataAttrs are the SMART attributes that predict failure (Backblaze's short list).
var ataAttrs = map[int]string{
	5: "reallocated_sectors", 187: "reported_uncorrectable", 188: "command_timeouts",
	197: "pending_sectors", 198: "offline_uncorrectable",
}

// EmitSmart reads `smartctl -j` output for one disk.
func EmitSmart(out sink.Sink, base map[string]string, dev string, b []byte, at time.Time) error {
	var r smartReport
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("hw ssh: smartctl output for %s is not JSON", dev)
	}
	a := sink.With(base, "hw.id", dev, "hw.name", nameOf(r.Model, dev), "hw.serial_number", r.Serial, "hw.type", "physical_disk")
	if r.SmartStatus != nil {
		state := "failed"
		if r.SmartStatus.Passed {
			state = "ok"
		}
		emitState(out, a, "physical_disk", state, at)
	}
	if r.Temperature != nil {
		out.Gauge("hw.temperature", "Cel", r.Temperature.Current, a, at)
	}
	if r.PowerOn != nil {
		out.Gauge("hw.physical_disk.power_on_time", "s", r.PowerOn.Hours*3600, a, at)
	}
	if r.ATA != nil {
		for _, t := range r.ATA.Table {
			if n, ok := ataAttrs[t.ID]; ok {
				out.Gauge("hw.physical_disk.smart", "1", t.Raw.Value, sink.With(a, "hw.smart.attribute", n), at)
			}
		}
	}
	if r.NVMe != nil {
		r.NVMe.emit(out, a, at)
	}
	return nil
}

type nvmeLog struct {
	CriticalWarning float64 `json:"critical_warning"`
	Temperature     float64 `json:"temperature"` // smartctl: Celsius; nvme-cli: Kelvin
	AvailSpare      float64 `json:"available_spare"`
	AvailSpareAlt   float64 `json:"avail_spare"`
	PercentageUsed  float64 `json:"percentage_used"`
	PercentUsedAlt  float64 `json:"percent_used"`
	MediaErrors     float64 `json:"media_errors"`
	UnsafeShutdowns float64 `json:"unsafe_shutdowns"`
	kelvin          bool
}

func (n *nvmeLog) emit(out sink.Sink, a map[string]string, at time.Time) {
	state := "ok"
	if n.CriticalWarning != 0 {
		state = "failed"
	}
	emitState(out, a, "physical_disk", state, at)
	temp := n.Temperature
	if n.kelvin && temp > 200 {
		temp -= 273.15
	}
	if temp > 0 {
		out.Gauge("hw.temperature", "Cel", temp, a, at)
	}
	out.Gauge("hw.physical_disk.endurance_utilization", "1", max(n.PercentageUsed, n.PercentUsedAlt)/100, a, at)
	out.Gauge("hw.physical_disk.spare_ratio", "1", max(n.AvailSpare, n.AvailSpareAlt)/100, a, at)
	out.Gauge("hw.errors", "{error}", n.MediaErrors, sink.With(a, "hw.error.type", "media"), at)
	out.Gauge("hw.physical_disk.unsafe_shutdowns", "{shutdown}", n.UnsafeShutdowns, a, at)
}

// EmitNVMe reads `nvme smart-log -o json` output for one controller.
func EmitNVMe(out sink.Sink, base map[string]string, dev string, b []byte, at time.Time) error {
	var n nvmeLog
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("hw ssh: nvme output for %s is not JSON", dev)
	}
	n.kelvin = true
	n.emit(out, sink.With(base, "hw.id", dev, "hw.name", dev, "hw.type", "physical_disk"), at)
	return nil
}

// MDArray is one Linux software RAID array of /proc/mdstat.
type MDArray struct {
	Name, Level string
	Active      bool
	Members     int // devices the array should have
	Up          int // devices that are in sync
	Rebuild     float64
	Rebuilding  bool
}

var (
	mdHead   = regexp.MustCompile(`^(md\d+)\s*:\s*(\S+)\s+(?:\(\S+\)\s+)?(\S+)?`)
	mdStatus = regexp.MustCompile(`\[(\d+)/(\d+)\]\s*\[([U_]+)\]`)
	mdSync   = regexp.MustCompile(`(recovery|resync|reshape|check)\s*=\s*([0-9.]+)%`)
)

// ParseMDStat reads /proc/mdstat: "md0 : active raid1 sdb1[1] sda1[0]" then a status line with
// "[2/2] [UU]" and, while rebuilding, "recovery = 12.6%".
func ParseMDStat(s string) []MDArray {
	var out []MDArray
	var cur *MDArray
	for _, line := range strings.Split(s, "\n") {
		if m := mdHead.FindStringSubmatch(line); m != nil {
			out = append(out, MDArray{Name: m[1], Active: m[2] == "active", Level: m[3]})
			cur = &out[len(out)-1]
			if !cur.Active {
				cur.Level = "" // an inactive array lists its members where the level would be
			}
			continue
		}
		if cur == nil {
			continue
		}
		if m := mdStatus.FindStringSubmatch(line); m != nil {
			cur.Members, _ = strconv.Atoi(m[1])
			cur.Up = strings.Count(m[3], "U")
		}
		if m := mdSync.FindStringSubmatch(line); m != nil {
			cur.Rebuilding = true
			cur.Rebuild, _ = strconv.ParseFloat(m[2], 64)
		}
	}
	return out
}

// EmitMDStat writes one logical disk state per array: failed when inactive, degraded when a
// member is missing or a rebuild runs, ok otherwise.
func EmitMDStat(out sink.Sink, base map[string]string, arrays []MDArray, at time.Time) {
	for _, m := range arrays {
		a := sink.With(base, "hw.id", m.Name, "hw.name", m.Name, "hw.raid.level", m.Level)
		state := "ok"
		switch {
		case !m.Active:
			state = "failed"
		case m.Members > 0 && m.Up < m.Members, m.Rebuilding:
			state = "degraded"
		}
		emitState(out, a, "logical_disk", state, at)
		if m.Members > 0 {
			out.Gauge("hw.logical_disk.members", "{disk}", float64(m.Members), a, at)
			out.Gauge("hw.logical_disk.members_up", "{disk}", float64(m.Up), a, at)
		}
		if m.Rebuilding {
			out.Gauge("hw.logical_disk.rebuild_progress", "1", m.Rebuild/100, a, at)
		}
	}
}
