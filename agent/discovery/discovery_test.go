package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/agent/snmp"
)

func TestTargetsExcludeAndBound(t *testing.T) {
	c := Config{Subnets: []string{"10.0.0.0/29", "10.0.0.4/30"}, Exclude: []string{"10.0.0.2", "10.0.0.4/31"}}
	got, err := c.Targets()
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, a := range got {
		s = append(s, a.String())
	}
	if strings.Join(s, ",") != "10.0.0.1,10.0.0.3,10.0.0.6" {
		t.Fatalf("%v", s)
	}
	if _, err := (Config{Subnets: []string{"10.0.0.0/8"}}).Targets(); err == nil {
		t.Fatal("a /8 sweep accepted")
	}
}

func TestSweepFindsOpenPortsAndSNMPVendor(t *testing.T) {
	ps, err := snmp.LoadProfiles("")
	if err != nil {
		t.Fatal(err)
	}
	pr := Prober{
		Timeout: 50 * time.Millisecond, Ports: []int{22, 443}, Communities: []string{"wrong", "public"}, Profiles: ps,
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			if addr == "10.0.0.1:22" || addr == "10.0.0.2:443" {
				c, s := net.Pipe()
				_ = s.Close()
				return c, nil
			}
			return nil, errors.New("refused")
		},
		Lookup: func(_ context.Context, a string) ([]string, error) { return []string{"host-" + a + "."}, nil },
		SysInfo: func(_ context.Context, tg snmp.Target) (string, string, string, error) {
			if tg.Address == "10.0.0.2" && tg.Community == "public" {
				return "1.3.6.1.4.1.9.1.516", "core-sw1", "Cisco IOS", nil
			}
			return "", "", "", errors.New("timeout")
		},
	}
	addrs := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")}
	found := Sweep(context.Background(), pr, addrs, 2)
	if len(found) != 2 || found[0].Name != "host-10.0.0.1" || len(found[0].Ports) != 1 ||
		found[1].Name != "core-sw1" || found[1].Vendor != "cisco" || !found[1].Community {
		t.Fatalf("%+v", found)
	}
	rec := &sink.Recorder{}
	Emit(rec, found, time.Now())
	var hosts int
	for _, s := range rec.Samples {
		if s.Name != "wt.discovery.host" {
			continue
		}
		hosts++
		if !strings.HasPrefix(s.Attrs[sink.ResourcePrefix+"host.id"], "scan:") || s.Attrs[sink.ResourcePrefix+"host.discovered_by"] != "subnet_scan" {
			t.Fatalf("%v", s.Attrs)
		}
	}
	if hosts != 2 {
		t.Fatalf("hosts %d", hosts)
	}
}
