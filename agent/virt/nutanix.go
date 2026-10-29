package virt

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// NutanixTarget is one Prism Element (or Prism Central cluster VIP), read with basic auth.
type NutanixTarget struct {
	Name        string `json:"name"`
	URL         string `json:"url"` // https://prism:9440
	Username    string `json:"username"`
	Password    string `json:"password"`
	PasswordEnv string `json:"password_env"`
	Insecure    bool   `json:"insecure"`
}

// NutanixConfig is the module's local configuration.
type NutanixConfig struct {
	common
	Targets []NutanixTarget `json:"targets"`
}

func (t NutanixTarget) validate() error {
	if t.Name == "" || t.Username == "" {
		return errName("nutanix")
	}
	return checkURL(t.URL)
}

// RunNutanix polls every Prism endpoint (v2 REST API) for hosts and VMs.
func RunNutanix(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c NutanixConfig
	return runTargets(ctx, "nutanix", raw, &c, &c.common, func() []NutanixTarget { return c.Targets },
		func(t NutanixTarget) string { return t.Name }, NutanixTarget.validate, PollNutanix, out, 60*time.Second)
}

type nxVM struct {
	UUID       string            `json:"uuid"`
	Name       string            `json:"name"`
	PowerState string            `json:"power_state"`
	VCPUs      float64           `json:"num_vcpus"`
	MemoryMB   float64           `json:"memory_mb"`
	HostName   string            `json:"host_name"`
	Stats      map[string]string `json:"stats"`
}

type nxHost struct {
	Name     string            `json:"name"`
	State    string            `json:"state"`
	NumVMs   float64           `json:"num_vms"`
	MemoryB  float64           `json:"memory_capacity_in_bytes"`
	Stats    map[string]string `json:"stats"`
	CPUCores float64           `json:"num_cpu_cores"`
}

func (t NutanixTarget) list(ctx context.Context, hc *http.Client, path string, dst any) error {
	pw := secretOf(t.Password, t.PasswordEnv)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(t.URL, "/")+"/PrismGateway/services/rest/v2.0"+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(t.Username, pw)
	return getJSON(hc, req, dst, pw, t.Username)
}

// ppm reads a Nutanix "..._ppm" stat (parts per million, as a string) as a percentage.
func ppm(stats map[string]string, key string) (float64, bool) {
	v, err := strconv.ParseFloat(stats[key], 64)
	return v / 10000, err == nil && stats[key] != ""
}

// PollNutanix reads hosts and VMs with their usage stats.
func PollNutanix(ctx context.Context, t NutanixTarget, out sink.Sink, at time.Time) error {
	if err := t.validate(); err != nil {
		return err
	}
	hc := newClient(t.Insecure)
	var hosts, vms struct {
		Entities []json.RawMessage `json:"entities"`
	}
	err := t.list(ctx, hc, "/hosts/?include_host_stats=true", &hosts)
	for _, e := range hosts.Entities {
		var h nxHost
		if json.Unmarshal(e, &h) != nil || h.Name == "" {
			continue
		}
		res, _ := hypervisorHost(h.Name)
		out.Gauge("nutanix.host.up", "", upGauge(h.State == "NORMAL"), sink.Res(res), at)
		out.Gauge("nutanix.host.vms", "{vms}", h.NumVMs, sink.Res(res), at)
		if v, ok := ppm(h.Stats, "hypervisor_cpu_usage_ppm"); ok {
			out.Gauge("nutanix.host.cpu.utilization", "%", v, sink.Res(res), at)
		}
		if v, ok := ppm(h.Stats, "hypervisor_memory_usage_ppm"); ok {
			out.Gauge("nutanix.host.memory.utilization", "%", v, sink.Res(res), at)
		}
	}
	if err2 := t.list(ctx, hc, "/vms/?include_vm_stats=true", &vms); err == nil {
		err = err2
	}
	for _, e := range vms.Entities {
		var v nxVM
		if json.Unmarshal(e, &v) != nil || v.UUID == "" {
			continue
		}
		r, _ := hypervisorHost(v.HostName)
		r["vm.id"], r["vm.name"] = t.Name+"/"+v.UUID, v.Name
		res := sink.Res(r)
		out.Gauge("nutanix.vm.up", "", upGauge(v.PowerState == "on"), sink.With(res, "nutanix.power_state", v.PowerState), at)
		out.Gauge("nutanix.vm.cpu.count", "", v.VCPUs, res, at)
		out.Gauge("nutanix.vm.memory.limit", "By", v.MemoryMB*1024*1024, res, at)
		if p, ok := ppm(v.Stats, "hypervisor_cpu_usage_ppm"); ok {
			out.Gauge("nutanix.vm.cpu.utilization", "%", p, res, at)
		}
		if p, ok := ppm(v.Stats, "memory_usage_ppm"); ok {
			out.Gauge("nutanix.vm.memory.utilization", "%", p, res, at)
		}
	}
	return err
}
