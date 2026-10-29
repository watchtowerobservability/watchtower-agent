// Package virt collects from hypervisors: vSphere through govmomi (PerformanceManager plus
// inventory) and Proxmox VE through its REST API. Each VM is an entity of kind vm whose parent is
// the host it runs on: the resource carries vm.id/vm.name and the hypervisor as host.id/host.name,
// and the worker derives the parent from host.* (nothing is stamped client-side).
//
// Credentials (vCenter password, Proxmox API token) exist only in the agent's own file or the
// environment variable it names; they are never logged, exported or put into a label or an error.
package virt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/performance"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// VSphereTarget is one vCenter or ESXi endpoint.
type VSphereTarget struct {
	Name        string `json:"name"`
	URL         string `json:"url"` // https://vcenter/sdk
	Username    string `json:"username"`
	Password    string `json:"password"`
	PasswordEnv string `json:"password_env"`
	Insecure    bool   `json:"insecure"` // skip TLS verification (self-signed vCenter)
}

// VSphereConfig is the module's local configuration.
type VSphereConfig struct {
	Enabled  *bool           `json:"enabled"`
	Interval string          `json:"interval"` // default 60s, floor 20s (real-time sample period)
	Targets  []VSphereTarget `json:"targets"`
}

const pollTimeout = 45 * time.Second

// perfCounters are the real-time counters read for hosts and VMs, with their scale to the unit.
var perfCounters = []struct {
	counter, metric, unit string
	scale                 float64
}{
	{"cpu.usage.average", "cpu.utilization", "%", 0.01},       // hundredths of a percent
	{"mem.usage.average", "memory.utilization", "%", 0.01},    // hundredths of a percent
	{"disk.usage.average", "disk.throughput", "By/s", 1024},   // KBps
	{"net.usage.average", "network.throughput", "By/s", 1024}, // KBps
}

func (t VSphereTarget) password() string {
	if t.Password != "" {
		return t.Password
	}
	return os.Getenv(t.PasswordEnv)
}

// RunVSphere polls every target in parallel, each under its own timeout.
func RunVSphere(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c VSphereConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 {
		<-ctx.Done()
		return nil
	}
	out = sink.Hoist(out)
	host.Every(ctx, host.Duration(c.Interval, 60*time.Second, 20*time.Second), func(ctx context.Context) {
		var wg sync.WaitGroup
		for _, t := range c.Targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, pollTimeout)
				defer cancel()
				host.Warn("vsphere "+t.Name, PollVSphere(cctx, t, out, time.Now()))
			}()
		}
		wg.Wait()
	})
	return nil
}

// PollVSphere logs in, reads the inventory and one real-time sample per host and VM, and logs out.
func PollVSphere(ctx context.Context, t VSphereTarget, out sink.Sink, at time.Time) (err error) {
	pw := t.password()
	defer func() { err = host.Redact(err, pw) }()
	u, err := url.Parse(t.URL)
	if err != nil {
		return errors.New("vsphere: bad url")
	}
	u.User = url.UserPassword(t.Username, pw)
	c, err := govmomi.NewClient(ctx, u, t.Insecure)
	if err != nil {
		return fmt.Errorf("vsphere %s: login: %w", t.Name, err)
	}
	defer func() { _ = c.Logout(context.WithoutCancel(ctx)) }()

	m := view.NewManager(c.Client)
	hv, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"HostSystem"}, true)
	if err != nil {
		return err
	}
	defer func() { _ = hv.Destroy(context.WithoutCancel(ctx)) }()
	vv, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		return err
	}
	defer func() { _ = vv.Destroy(context.WithoutCancel(ctx)) }()

	var hosts []mo.HostSystem
	if err := hv.Retrieve(ctx, []string{"HostSystem"}, []string{"name"}, &hosts); err != nil {
		return err
	}
	var vms []mo.VirtualMachine
	if err := vv.Retrieve(ctx, []string{"VirtualMachine"}, []string{"name", "summary.config.uuid", "summary.config.instanceUuid", "runtime.host", "runtime.powerState"}, &vms); err != nil {
		return err
	}
	hostName := map[types.ManagedObjectReference]string{}
	for _, h := range hosts {
		hostName[h.Reference()] = h.Name
	}

	// entity resource per managed object; an ESXi host that is the agent's own host keeps the
	// agent's resource (nil), so its identity cannot flap.
	ents := map[types.ManagedObjectReference]entity{}
	var refs []types.ManagedObjectReference
	for _, h := range hosts {
		res, own := hypervisorHost(h.Name)
		if own {
			res = nil
		}
		ents[h.Reference()] = entity{kind: "host", res: res}
		refs = append(refs, h.Reference())
	}
	for _, v := range vms {
		hn := ""
		if v.Runtime.Host != nil {
			hn = hostName[*v.Runtime.Host]
		}
		id := v.Summary.Config.InstanceUuid // unique per vCenter; the BIOS uuid is shared by clones
		if id == "" {
			id = v.Summary.Config.Uuid
		}
		if id == "" || hn == "" {
			continue // no stable identity or parent: not an entity
		}
		r, _ := hypervisorHost(hn)
		r["vm.id"], r["vm.name"] = id, v.Name
		ents[v.Reference()] = entity{kind: "vm", res: r}
		refs = append(refs, v.Reference())
		out.Gauge("vsphere.vm.info", "", 1, sink.With(sink.Res(r), "vsphere.power_state", string(v.Runtime.PowerState)), at)
	}
	return samplePerf(ctx, c, refs, ents, out, at)
}

type entity struct {
	kind string
	res  map[string]string
}

func samplePerf(ctx context.Context, c *govmomi.Client, refs []types.ManagedObjectReference, ents map[types.ManagedObjectReference]entity, out sink.Sink, at time.Time) error {
	if len(refs) == 0 {
		return nil
	}
	pm := performance.NewManager(c.Client)
	names := make([]string, 0, len(perfCounters))
	for _, pc := range perfCounters {
		names = append(names, pc.counter)
	}
	raw, err := pm.SampleByName(ctx, types.PerfQuerySpec{MaxSample: 1, IntervalId: 20}, names, refs)
	if err != nil {
		return err
	}
	ems, err := pm.ToMetricSeries(ctx, raw)
	if err != nil {
		return err
	}
	for _, em := range ems {
		e := ents[em.Entity]
		for _, s := range em.Value {
			if s.Instance != "" || len(s.Value) == 0 {
				continue // aggregate only
			}
			for _, pc := range perfCounters {
				if pc.counter == s.Name {
					out.Gauge("vsphere."+e.kind+"."+pc.metric, pc.unit, float64(s.Value[len(s.Value)-1])*pc.scale, sink.Res(e.res), at)
				}
			}
		}
	}
	return nil
}
