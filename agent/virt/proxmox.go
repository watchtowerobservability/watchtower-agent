package virt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// ProxmoxTarget is one Proxmox VE cluster endpoint, read with an API token (PVEAPIToken).
type ProxmoxTarget struct {
	Name      string `json:"name"`
	URL       string `json:"url"`      // https://pve:8006 (http only for loopback)
	TokenID   string `json:"token_id"` // user@realm!tokenname
	Secret    string `json:"token_secret"`
	SecretEnv string `json:"token_secret_env"`
	Insecure  bool   `json:"insecure"`
}

// ProxmoxConfig is the module's local configuration.
type ProxmoxConfig struct {
	Enabled  *bool           `json:"enabled"`
	Interval string          `json:"interval"` // default 30s, floor 10s
	Targets  []ProxmoxTarget `json:"targets"`
}

const maxPVEBody = 8 << 20

func (t ProxmoxTarget) secret() string {
	if t.Secret != "" {
		return t.Secret
	}
	return os.Getenv(t.SecretEnv)
}

// RunProxmox polls every target in parallel, each under its own timeout.
func RunProxmox(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c ProxmoxConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 {
		<-ctx.Done()
		return nil
	}
	for _, t := range c.Targets {
		if err := t.validate(); err != nil {
			return err
		}
	}
	out = sink.Hoist(out)
	host.Every(ctx, host.Duration(c.Interval, 30*time.Second, 10*time.Second), func(ctx context.Context) {
		var wg sync.WaitGroup
		for _, t := range c.Targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
				defer cancel()
				host.Warn("proxmox "+t.Name, PollProxmox(cctx, t, out, time.Now()))
			}()
		}
		wg.Wait()
	})
	return nil
}

// validate refuses a token over plain http to anything but a loopback address.
func (t ProxmoxTarget) validate() error {
	if t.Name == "" {
		return errors.New("proxmox: every target needs a name (it is part of the VM identity)")
	}
	u, err := url.Parse(t.URL)
	if err != nil || u.Host == "" {
		return errors.New("proxmox: bad url")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("proxmox: url must be https (http only for loopback)")
		}
	}
	return nil
}

// flexInt decodes a JSON number or a numeric string (PVE returns lxc vmid as a string).
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	n, err := strconv.Atoi(strings.Trim(string(b), `"`))
	if err != nil {
		return fmt.Errorf("not an integer: %s", b)
	}
	*f = flexInt(n)
	return nil
}

type pveGuest struct {
	VMID      flexInt `json:"vmid"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	CPU       float64 `json:"cpu"`  // fraction of the guest's cpus
	CPUs      float64 `json:"cpus"` // configured vcpus (qemu and lxc lists)
	MaxCPU    float64 `json:"maxcpu"`
	Mem       float64 `json:"mem"`
	MaxMem    float64 `json:"maxmem"`
	Uptime    float64 `json:"uptime"`
	NetIn     float64 `json:"netin"`
	NetOut    float64 `json:"netout"`
	DiskRead  float64 `json:"diskread"`
	DiskWrite float64 `json:"diskwrite"`
}

type pveNode struct {
	Node   string  `json:"node"`
	Status string  `json:"status"`
	CPU    float64 `json:"cpu"`
	Mem    float64 `json:"mem"`
	MaxMem float64 `json:"maxmem"`
	Uptime float64 `json:"uptime"`
}

func (t ProxmoxTarget) client() *http.Client {
	return newClient(t.Insecure)
}

func (t ProxmoxTarget) get(ctx context.Context, hc *http.Client, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(t.URL, "/")+"/api2/json"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+t.TokenID+"="+t.secret())
	resp, err := hc.Do(req)
	if err != nil {
		return host.Redact(err, t.secret())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxmox %s: %s: status %d", t.Name, path, resp.StatusCode)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPVEBody)).Decode(&env); err != nil {
		return fmt.Errorf("proxmox %s: %s: bad response", t.Name, path)
	}
	return json.Unmarshal(env.Data, dst)
}

// PollProxmox reads nodes, then the qemu and lxc guests of each, and emits their status.
func PollProxmox(ctx context.Context, t ProxmoxTarget, out sink.Sink, at time.Time) error {
	if err := t.validate(); err != nil {
		return err
	}
	hc := t.client()
	var nodes []pveNode
	if err := t.get(ctx, hc, "/nodes", &nodes); err != nil {
		return err
	}
	var firstErr error
	for _, n := range nodes {
		if n.Node == "" {
			continue
		}
		hres, own := hypervisorHost(n.Node)
		if own {
			hres = nil // the agent's own resource already describes this host
		}
		up := 0.0
		if n.Status == "online" {
			up = 1
		}
		out.Gauge("proxmox.node.up", "", up, sink.Res(hres), at)
		out.Gauge("proxmox.node.cpu.utilization", "%", n.CPU*100, sink.Res(hres), at)
		out.Gauge("proxmox.node.memory.usage", "By", n.Mem, sink.Res(hres), at)
		out.Gauge("proxmox.node.memory.limit", "By", n.MaxMem, sink.Res(hres), at)
		for _, kind := range []string{"qemu", "lxc"} {
			var gs []pveGuest
			if err := t.get(ctx, hc, "/nodes/"+url.PathEscape(n.Node)+"/"+kind, &gs); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			for _, g := range gs {
				emitGuest(out, t.Name, n.Node, kind, g, at)
			}
		}
	}
	return firstErr
}

func emitGuest(out sink.Sink, target, node, kind string, g pveGuest, at time.Time) {
	r, _ := hypervisorHost(node)
	r["vm.id"], r["vm.name"], r["proxmox.kind"] = target+"/"+strconv.Itoa(int(g.VMID)), g.Name, kind
	res := sink.Res(r)
	up := 0.0
	if g.Status == "running" {
		up = 1
	}
	p := "proxmox." + kind + "."
	out.Gauge(p+"up", "", up, sink.With(res, "proxmox.status", g.Status), at)
	out.Gauge(p+"cpu.utilization", "%", g.CPU*100, res, at)
	cpus := g.CPUs
	if cpus == 0 {
		cpus = g.MaxCPU
	}
	out.Gauge(p+"cpu.count", "", cpus, res, at)
	out.Gauge(p+"memory.usage", "By", g.Mem, res, at)
	out.Gauge(p+"memory.limit", "By", g.MaxMem, res, at)
	out.Gauge(p+"uptime", "s", g.Uptime, res, at)
	out.Sum(p+"network.io.receive", "By", g.NetIn, res, at)
	out.Sum(p+"network.io.transmit", "By", g.NetOut, res, at)
	out.Sum(p+"disk.io.read", "By", g.DiskRead, res, at)
	out.Sum(p+"disk.io.write", "By", g.DiskWrite, res, at)
}
