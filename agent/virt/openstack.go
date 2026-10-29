package virt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// OpenStackTarget is one cloud: Keystone v3 password auth, then Nova (compute) read-only calls.
type OpenStackTarget struct {
	Name        string `json:"name"`
	AuthURL     string `json:"auth_url"` // https://keystone:5000
	Username    string `json:"username"`
	Password    string `json:"password"`
	PasswordEnv string `json:"password_env"`
	Project     string `json:"project"`
	Domain      string `json:"domain"` // user and project domain, default "Default"
	Region      string `json:"region"`
	Insecure    bool   `json:"insecure"`
}

// OpenStackConfig is the module's local configuration.
type OpenStackConfig struct {
	common
	Targets []OpenStackTarget `json:"targets"`
}

func (t OpenStackTarget) validate() error {
	if t.Name == "" || t.Username == "" || t.Project == "" {
		return errors.New("openstack: every target needs name, username and project")
	}
	return checkURL(t.AuthURL)
}

// RunOpenStack polls every cloud for hypervisors and servers.
func RunOpenStack(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c OpenStackConfig
	return runTargets(ctx, "openstack", raw, &c, &c.common, func() []OpenStackTarget { return c.Targets },
		func(t OpenStackTarget) string { return t.Name }, OpenStackTarget.validate, PollOpenStack, out, 60*time.Second)
}

type osCatalogEntry struct {
	Type      string `json:"type"`
	Endpoints []struct {
		Interface string `json:"interface"`
		Region    string `json:"region"`
		URL       string `json:"url"`
	} `json:"endpoints"`
}

// login returns the token and the public compute endpoint.
func (t OpenStackTarget) login(ctx context.Context, hc *http.Client, pw string) (token, compute string, err error) {
	dom := map[string]string{"name": "Default"}
	if t.Domain != "" {
		dom["name"] = t.Domain
	}
	body, _ := json.Marshal(map[string]any{"auth": map[string]any{
		"identity": map[string]any{"methods": []string{"password"}, "password": map[string]any{
			"user": map[string]any{"name": t.Username, "domain": dom, "password": pw}}},
		"scope": map[string]any{"project": map[string]any{"name": t.Project, "domain": dom}},
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(t.AuthURL, "/")+"/v3/auth/tokens", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", host.Redact(err, pw)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", "", errors.New("openstack: keystone refused the login")
	}
	var env struct {
		Token struct {
			Catalog []osCatalogEntry `json:"catalog"`
		} `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", "", errors.New("openstack: bad keystone response")
	}
	for _, c := range env.Token.Catalog {
		for _, e := range c.Endpoints {
			if c.Type == "compute" && e.Interface == "public" && (t.Region == "" || e.Region == t.Region) {
				return resp.Header.Get("X-Subject-Token"), strings.TrimRight(e.URL, "/"), checkURL(e.URL)
			}
		}
	}
	return "", "", errors.New("openstack: no public compute endpoint in the catalog")
}

type osServer struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Host   string `json:"OS-EXT-SRV-ATTR:host"`
}

type osHypervisor struct {
	Name     string  `json:"hypervisor_hostname"`
	State    string  `json:"state"`
	Status   string  `json:"status"`
	VCPUs    float64 `json:"vcpus"`
	VCPUsUse float64 `json:"vcpus_used"`
	MemMB    float64 `json:"memory_mb"`
	MemMBUse float64 `json:"memory_mb_used"`
	Running  float64 `json:"running_vms"`
}

// PollOpenStack logs in once per poll and reads /os-hypervisors/detail and /servers/detail.
func PollOpenStack(ctx context.Context, t OpenStackTarget, out sink.Sink, at time.Time) error {
	if err := t.validate(); err != nil {
		return err
	}
	pw := secretOf(t.Password, t.PasswordEnv)
	hc := newClient(t.Insecure)
	token, compute, err := t.login(ctx, hc, pw)
	if err != nil {
		return err
	}
	get := func(path string, dst any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, compute+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Auth-Token", token)
		return getJSON(hc, req, dst, pw, token)
	}
	var hv struct {
		Hypervisors []osHypervisor `json:"hypervisors"`
	}
	var sv struct {
		Servers []osServer `json:"servers"`
	}
	err = get("/os-hypervisors/detail", &hv) // needs an admin role; a member sees servers only
	for _, h := range hv.Hypervisors {
		res, _ := hypervisorHost(h.Name)
		out.Gauge("openstack.hypervisor.up", "", upGauge(h.State == "up" && h.Status == "enabled"), sink.Res(res), at)
		out.Gauge("openstack.hypervisor.vcpus.limit", "", h.VCPUs, sink.Res(res), at)
		out.Gauge("openstack.hypervisor.vcpus.usage", "", h.VCPUsUse, sink.Res(res), at)
		out.Gauge("openstack.hypervisor.memory.limit", "By", h.MemMB*1024*1024, sink.Res(res), at)
		out.Gauge("openstack.hypervisor.memory.usage", "By", h.MemMBUse*1024*1024, sink.Res(res), at)
		out.Gauge("openstack.hypervisor.vms", "{vms}", h.Running, sink.Res(res), at)
	}
	if err2 := get("/servers/detail?limit=1000&all_tenants=true", &sv); err == nil {
		err = err2
	}
	for _, s := range sv.Servers {
		r, _ := hypervisorHost(s.Host)
		r["vm.id"], r["vm.name"] = t.Name+"/"+s.ID, s.Name
		out.Gauge("openstack.server.up", "", upGauge(s.Status == "ACTIVE"), sink.With(sink.Res(r), "openstack.status", s.Status), at)
	}
	return err
}
