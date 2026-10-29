package virt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// LibvirtTarget is one libvirt daemon read through the `virsh` binary in read-only mode
// (`virsh -r`), so nothing the agent runs can change a domain. Path and URI are local-file only.
type LibvirtTarget struct {
	Name string `json:"name"`
	Path string `json:"path"` // virsh binary
	URI  string `json:"uri"`  // default qemu:///system
}

// LibvirtConfig is the module's local configuration.
type LibvirtConfig struct {
	common
	Targets []LibvirtTarget `json:"targets"`
}

func (t LibvirtTarget) validate() error {
	if t.Name == "" || t.Path == "" {
		return errors.New("libvirt: every target needs a name and the path of virsh")
	}
	return nil
}

// RunLibvirt polls every daemon.
func RunLibvirt(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c LibvirtConfig
	return runTargets(ctx, "libvirt", raw, &c, &c.common, func() []LibvirtTarget { return c.Targets },
		func(t LibvirtTarget) string { return t.Name }, LibvirtTarget.validate, PollLibvirt, out, 30*time.Second)
}

// PollLibvirt runs `virsh -r domstats --state --cpu-total --balloon --vcpu` and emits one VM each.
func PollLibvirt(ctx context.Context, t LibvirtTarget, out sink.Sink, at time.Time) error {
	if err := t.validate(); err != nil {
		return err
	}
	uri := t.URI
	if uri == "" {
		uri = "qemu:///system"
	}
	cmd := exec.CommandContext(ctx, t.Path, "-r", "-c", uri, "domstats", "--state", "--cpu-total", "--balloon")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return errors.New("libvirt: virsh failed") // stderr may name the connection
	}
	hres, _ := hypervisorHost(hostName())
	for _, d := range ParseDomstats(buf.String()) {
		r := map[string]string{"host.name": hres["host.name"], "vm.id": t.Name + "/" + d.Name, "vm.name": d.Name}
		res := sink.Res(r)
		out.Gauge("libvirt.domain.up", "", upGauge(d.Num["state.state"] == 1), res, at) // 1 = VIR_DOMAIN_RUNNING
		out.Sum("libvirt.domain.cpu.time", "ns", d.Num["cpu.time"], res, at)
		out.Gauge("libvirt.domain.memory.limit", "By", d.Num["balloon.maximum"]*1024, res, at)
		out.Gauge("libvirt.domain.memory.usage", "By", d.Num["balloon.current"]*1024, res, at)
	}
	return nil
}

func hostName() string {
	h, _ := os.Hostname()
	return h
}

// Domain is one block of `virsh domstats` output.
type Domain struct {
	Name string
	Num  map[string]float64
}

// ParseDomstats reads `Domain: 'name'` blocks of indented `key=value` lines.
func ParseDomstats(s string) []Domain {
	var out []Domain
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if n, ok := strings.CutPrefix(ln, "Domain: "); ok {
			out = append(out, Domain{Name: strings.Trim(n, `'"`), Num: map[string]float64{}})
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if f, err := strconv.ParseFloat(v, 64); ok && err == nil && len(out) > 0 {
			out[len(out)-1].Num[k] = f
		}
	}
	return out
}
