package snmp

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestCiscoProfileLoads(t *testing.T) {
	ps, err := LoadProfiles("")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) < 100 {
		t.Fatalf("only %d vendor profiles", len(ps))
	}
	p, ok := ps.Match(".1.3.6.1.4.1.9.1.516")
	if !ok || p.Vendor != "cisco" || p.Class != "network" {
		t.Fatalf("cisco = %+v %v", p, ok)
	}
	all, err := Manifests("")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if _, err := pick(all, p.Manifests()); err != nil {
			t.Fatalf("%s: %v", p.Vendor, err)
		}
	}
	if _, ok := ps.Match("1.3.6.1.4.1.99999999.1"); ok {
		t.Fatal("unknown vendor matched")
	}
	if _, ok := ps.Match("1.3.6.1.2.1.1"); ok {
		t.Fatal("non-enterprise oid matched")
	}
}

func TestSubnetDiscoveryFindsProfiledHosts(t *testing.T) {
	hosts, err := SubnetHosts("10.0.0.0/30")
	if err != nil || len(hosts) != 2 {
		t.Fatalf("hosts %v %v", hosts, err)
	}
	if _, err := SubnetHosts("10.0.0.0/8"); err == nil {
		t.Fatal("a /8 sweep must be refused")
	}
	ps, _ := LoadProfiles("")
	got, err := Discover(context.Background(), ps, hosts, 2, func(_ context.Context, a netip.Addr) (string, error) {
		if a == hosts[0] {
			return "1.3.6.1.4.1.318.1.3", nil
		}
		return "", errors.New("timeout")
	})
	if err != nil || len(got) != 1 || got[0].Profile.Vendor != "apc" {
		t.Fatalf("found %+v %v", got, err)
	}
}
