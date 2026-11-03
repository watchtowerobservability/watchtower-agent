// Package discovery is the agent's opt-in subnet scan (INF-021): every interval it sweeps the
// configured CIDRs (at most 4096 addresses each), tries a TCP connect to a short list of
// well-known ports and, when communities are configured, asks SNMP for sysObjectID. Every host
// that answers becomes a host entity (host.discovered_by = subnet_scan) with its open ports and
// SNMP vendor. It uses plain TCP connects, so it needs no privileges; it never scans anything the
// agent's own file does not name.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/agent/snmp"
)

const (
	maxSubnets     = 16
	maxConcurrency = 128
	maxPorts       = 32
)

// DefaultPorts are tried when the config lists none.
var DefaultPorts = []int{22, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 9100}

// Config is the discovery module's config. Remote config may only toggle it and set interval.
type Config struct {
	Enabled     *bool    `json:"enabled"`
	Interval    string   `json:"interval"` // default 1h, at least 10m
	Subnets     []string `json:"subnets"`
	Exclude     []string `json:"exclude"` // addresses or CIDRs never probed
	Ports       []int    `json:"ports"`
	Concurrency int      `json:"concurrency"` // default 32
	Timeout     string   `json:"timeout"`     // per probe, default 500ms
	SNMP        *struct {
		Communities []string `json:"communities"`
		Version     string   `json:"version"` // 1 or 2c (default)
		ProfileDir  string   `json:"profile_dir"`
	} `json:"snmp"`
}

// Found is one host that answered.
type Found struct {
	Addr      netip.Addr
	Name      string // reverse DNS or SNMP sysName
	Ports     []int
	ObjectID  string
	SysDescr  string
	Vendor    string
	Class     string
	Community bool // answered SNMP
}

// Prober is what a sweep uses; tests replace it.
type Prober struct {
	Timeout     time.Duration
	Ports       []int
	Communities []string
	Version     string
	Profiles    snmp.Profiles
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	Lookup      func(ctx context.Context, addr string) ([]string, error)
	SysInfo     func(ctx context.Context, t snmp.Target) (string, string, string, error)
}

// Probe checks one address; ok is false when nothing answered.
func (p Prober) Probe(ctx context.Context, a netip.Addr) (Found, bool) {
	f := Found{Addr: a}
	for _, port := range p.Ports {
		c, cancel := context.WithTimeout(ctx, p.Timeout)
		conn, err := p.Dial(c, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		cancel()
		if err == nil {
			_ = conn.Close()
			f.Ports = append(f.Ports, port)
		}
	}
	for _, comm := range p.Communities {
		c, cancel := context.WithTimeout(ctx, 2*p.Timeout)
		oid, name, descr, err := p.SysInfo(c, snmp.Target{Name: a.String(), Address: a.String(), Version: p.Version,
			Community: comm, Timeout: p.Timeout.String(), Retries: 1})
		cancel()
		if err == nil && oid != "" {
			f.ObjectID, f.SysDescr, f.Community = oid, sink.Truncate(descr, 256), true
			f.Name = name
			if pr, ok := p.Profiles.Match(oid); ok {
				f.Vendor, f.Class = pr.Vendor, pr.Class
			}
			break
		}
	}
	if len(f.Ports) == 0 && !f.Community {
		return f, false
	}
	if f.Name == "" && p.Lookup != nil {
		c, cancel := context.WithTimeout(ctx, p.Timeout)
		if names, err := p.Lookup(c, a.String()); err == nil && len(names) > 0 {
			f.Name = strings.TrimSuffix(names[0], ".")
		}
		cancel()
	}
	return f, true
}

// Sweep probes every address with at most conc probes at once, in address order.
func Sweep(ctx context.Context, p Prober, addrs []netip.Addr, conc int) []Found {
	res := make([]*Found, len(addrs))
	sem := make(chan struct{}, max(conc, 1))
	var wg sync.WaitGroup
	for i, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			if f, ok := p.Probe(ctx, a); ok {
				res[i] = &f
			}
		}()
	}
	wg.Wait()
	var out []Found
	for _, f := range res {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// Emit writes one wt.discovery.host sample per host, with host.* resource attributes so the
// worker records it as a host entity. host.id is "scan:<ip>" so a found host never merges into
// the scanning agent's own host.
func Emit(out sink.Sink, found []Found, at time.Time) {
	for _, f := range found {
		ip := f.Addr.String()
		name := f.Name
		if name == "" {
			name = ip
		}
		ports := make([]string, len(f.Ports))
		for i, p := range f.Ports {
			ports[i] = strconv.Itoa(p)
		}
		res := map[string]string{
			"host.id": "scan:" + ip, "host.name": sink.Truncate(name, 255), "host.ip": ip, "os.type": "",
			"host.discovered_by": "subnet_scan", "host.open_ports": strings.Join(ports, ","),
		}
		for k, v := range map[string]string{"host.snmp.sys_object_id": f.ObjectID, "host.snmp.sys_descr": f.SysDescr,
			"host.vendor": f.Vendor, "host.device_class": f.Class} {
			if v != "" {
				res[k] = v
			}
		}
		out.Gauge("wt.discovery.host", "1", 1, sink.Res(res), at)
	}
	out.Gauge("wt.discovery.hosts_found", "{host}", float64(len(found)), nil, at)
}

// Targets expands the configured subnets minus the exclusions.
func (c Config) Targets() ([]netip.Addr, error) {
	if len(c.Subnets) > maxSubnets {
		return nil, fmt.Errorf("discovery: at most %d subnets", maxSubnets)
	}
	var ex []netip.Prefix
	for _, e := range c.Exclude {
		if !strings.Contains(e, "/") {
			a, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("discovery: bad exclude %q", e)
			}
			e = netip.PrefixFrom(a, a.BitLen()).String()
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("discovery: bad exclude %q", e)
		}
		ex = append(ex, p)
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, s := range c.Subnets {
		hs, err := snmp.SubnetHosts(s)
		if err != nil {
			return nil, err
		}
	next:
		for _, h := range hs {
			for _, p := range ex {
				if p.Contains(h) {
					continue next
				}
			}
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

// Run sweeps every interval until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("discovery config: %w", err)
		}
	}
	addrs, err := c.Targets()
	if err != nil {
		return err
	}
	ports := c.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	if len(ports) > maxPorts {
		return errors.New("discovery: too many ports")
	}
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			return fmt.Errorf("discovery: bad port %d", p)
		}
	}
	if c.Enabled != nil && !*c.Enabled || len(addrs) == 0 {
		<-ctx.Done()
		return nil
	}
	var d net.Dialer
	pr := Prober{Timeout: host.Duration(c.Timeout, 500*time.Millisecond, 50*time.Millisecond), Ports: ports,
		Dial: d.DialContext, Lookup: net.DefaultResolver.LookupAddr, SysInfo: snmp.SysInfo}
	if c.SNMP != nil {
		pr.Communities, pr.Version = c.SNMP.Communities, c.SNMP.Version
		if pr.Profiles, err = snmp.LoadProfiles(c.SNMP.ProfileDir); err != nil {
			return err
		}
	}
	conc := c.Concurrency
	if conc <= 0 {
		conc = 32
	}
	conc = min(conc, maxConcurrency)
	every := max(host.Duration(c.Interval, time.Hour, 10*time.Minute), 10*time.Minute)
	t := time.NewTicker(every)
	defer t.Stop()
	out = sink.Hoist(out)
	for {
		Emit(out, Sweep(ctx, pr, addrs, conc), time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
