package snmp

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yaml
var profileFS embed.FS

// Profile maps a vendor (the enterprise number of sysObjectID) to a device class.
type Profile struct {
	Enterprise int    `yaml:"enterprise"`
	Vendor     string `yaml:"vendor"`
	Class      string `yaml:"class"`
	// VendorManifests lists the vendor's own manifests (CPU, memory, environment), polled on top of the
	// class set.
	VendorManifests []string `yaml:"manifests,omitempty"`
}

// classManifests is what each device class polls.
var classManifests = map[string][]string{
	"network": {"bgp4-mib", "entity-sensor-mib", "if-mib"},
	"server":  {"host-resources-mib", "if-mib"},
	"ups":     {"if-mib", "ups-mib"},
	"printer": {"host-resources-mib", "if-mib"},
}

// Manifests returns the manifest names the profile polls: the class set plus the vendor's own.
func (p Profile) Manifests() []string {
	out := append([]string(nil), classManifests[p.Class]...)
	for _, m := range p.VendorManifests {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// Profiles is a set of vendor profiles keyed by enterprise number.
type Profiles map[int]Profile

type profileFile struct {
	Profiles []Profile `yaml:"profiles"`
}

// LoadProfiles reads the embedded vendor profiles, then *.yaml in dir (local config) which
// replace entries with the same enterprise number.
func LoadProfiles(dir string) (Profiles, error) {
	out := Profiles{}
	add := func(name string, b []byte) error {
		var f profileFile
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		for _, p := range f.Profiles {
			if p.Enterprise <= 0 || p.Vendor == "" || classManifests[p.Class] == nil {
				return fmt.Errorf("%s: bad profile %+v", name, p)
			}
			out[p.Enterprise] = p
		}
		return nil
	}
	ents, err := profileFS.ReadDir("profiles")
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		b, err := profileFS.ReadFile("profiles/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := add(e.Name(), b); err != nil {
			return nil, err
		}
	}
	if dir == "" {
		return out, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := add(filepath.Base(f), b); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Match finds the profile of a sysObjectID such as 1.3.6.1.4.1.9.1.516.
func (ps Profiles) Match(sysObjectID string) (Profile, bool) {
	rest, ok := strings.CutPrefix(norm(sysObjectID), "1.3.6.1.4.1.")
	if !ok {
		return Profile{}, false
	}
	n, _, _ := strings.Cut(rest, ".")
	e, err := strconv.Atoi(n)
	if err != nil {
		return Profile{}, false
	}
	p, ok := ps[e]
	return p, ok
}

// profileManifests reads the device's sysObjectID and returns the manifests of its vendor
// profile (INF-015). ok is false when the device did not answer, so the next poll asks again; a
// vendor without a profile keeps fallback.
func profileManifests(ctx context.Context, t Target, ps Profiles, all map[string]Manifest, fallback []Manifest) ([]Manifest, bool) {
	oid, _, _, err := SysInfo(ctx, t)
	if err != nil || oid == "" {
		return fallback, false
	}
	p, found := ps.Match(oid)
	if !found {
		return fallback, true
	}
	ms, err := pick(all, p.Manifests())
	if err != nil {
		slog.Warn("snmp vendor profile names an unknown manifest", "device", t.Name, "vendor", p.Vendor, "error", err)
		return fallback, true
	}
	slog.Info("snmp vendor profile", "device", t.Name, "vendor", p.Vendor, "class", p.Class)
	return ms, true
}

// MaxSubnetHosts bounds a discovery sweep.
const MaxSubnetHosts = 4096

// SubnetHosts lists the host addresses of a CIDR (network and broadcast excluded for IPv4).
func SubnetHosts(cidr string) ([]netip.Addr, error) {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	pfx = pfx.Masked()
	if pfx.Addr().BitLen()-pfx.Bits() > 12 {
		return nil, fmt.Errorf("snmp discovery: %s has more than %d hosts", cidr, MaxSubnetHosts)
	}
	var out []netip.Addr
	for a := pfx.Addr(); pfx.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if pfx.Addr().Is4() && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// Found is one discovered device.
type Found struct {
	Addr    netip.Addr
	Profile Profile
}

// Discover asks every host for its sysObjectID (probe) with at most conc probes at once and
// returns the hosts whose vendor has a profile, in address order.
func Discover(ctx context.Context, ps Profiles, hosts []netip.Addr, conc int,
	probe func(context.Context, netip.Addr) (string, error)) ([]Found, error) {
	if probe == nil {
		return nil, errors.New("snmp discovery: no probe")
	}
	res := make([]*Found, len(hosts))
	sem := make(chan struct{}, max(conc, 1))
	var wg sync.WaitGroup
	for i, h := range hosts {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			if ctx.Err() != nil {
				return
			}
			if oid, err := probe(ctx, h); err == nil {
				if p, ok := ps.Match(oid); ok {
					res[i] = &Found{h, p}
				}
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
	return out, ctx.Err()
}
