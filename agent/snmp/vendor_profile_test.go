package snmp

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The ten vendors with their own polling manifest (INF-015).
var vendorManifests = map[int]string{
	9: "vendor-cisco", 2636: "vendor-juniper", 12356: "vendor-fortinet", 25461: "vendor-paloalto",
	3375: "vendor-f5", 14823: "vendor-aruba", 30065: "vendor-arista", 11: "vendor-hpe",
	674: "vendor-dell", 14988: "vendor-mikrotik",
}

func TestVendorProfilesLoadAndBindManifests(t *testing.T) {
	ps, err := LoadProfiles("")
	if err != nil {
		t.Fatal(err)
	}
	all, err := Manifests("")
	if err != nil {
		t.Fatal(err)
	}
	for ent, name := range vendorManifests {
		p, ok := ps.Match("1.3.6.1.4.1." + strconv.Itoa(ent) + ".1.1")
		if !ok || !slices.Contains(p.Manifests(), name) {
			t.Fatalf("enterprise %d: profile %+v does not poll %s", ent, p, name)
		}
		if _, err := pick(all, p.Manifests()); err != nil {
			t.Fatalf("enterprise %d: %v", ent, err)
		}
		m := all[name]
		if len(m.Scalars)+len(m.Tables) == 0 {
			t.Fatalf("%s is empty", name)
		}
		// every OID of a vendor manifest lives under that vendor's enterprise subtree
		root := "1.3.6.1.4.1." + strconv.Itoa(ent) + "."
		for _, s := range m.Scalars {
			if !strings.HasPrefix(s.OID, root) || !strings.HasSuffix(s.OID, ".0") || s.Metric == "" {
				t.Fatalf("%s scalar %+v", name, s)
			}
		}
		for _, tb := range m.Tables {
			if !strings.HasPrefix(tb.OID, root) || len(tb.Items) == 0 {
				t.Fatalf("%s table %s", name, tb.Name)
			}
		}
	}
}

func vOID(oid, val string) vb { return vb{oid, 0x06, encOID(val)} }

func TestTargetWithoutManifestsPollsVendorProfile(t *testing.T) {
	f, addr := startFake(t)
	f.set(vOID("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.12356.101.1.3004"))
	f.set(vStr("1.3.6.1.2.1.1.5.0", "fgt1"))
	f.set(vGauge("1.3.6.1.4.1.12356.101.4.1.3.0", 37))
	f.set(vGauge("1.3.6.1.4.1.12356.101.4.1.8.0", 1200))
	tg := Target{Name: "fw1", Address: addr, Community: "public", Timeout: "500ms"}
	ps, _ := LoadProfiles("")
	all, _ := Manifests("")
	fallback, _ := pick(all, nil)
	ms, ok := profileManifests(context.Background(), tg, ps, all, fallback)
	if !ok {
		t.Fatal("device did not answer")
	}
	names := make([]string, 0, len(ms))
	for _, m := range ms {
		names = append(names, m.Name)
	}
	if !slices.Contains(names, "vendor-fortinet") || slices.Contains(names, "ups-mib") {
		t.Fatalf("picked %v", names)
	}
	rec := &sink.Recorder{}
	if err := PollTarget(context.Background(), tg, ms, &Rates{}, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, s := range rec.Samples {
		got[s.Name] = s.Value
	}
	if got["snmp.cpu.utilization"] != 37 || got["snmp.sessions.active"] != 1200 {
		t.Fatalf("samples %v", got)
	}

	// a device that does not answer keeps the fallback and is asked again next poll
	down := Target{Name: "x", Address: "127.0.0.1:1", Community: "public", Timeout: "100ms"}
	if ms, ok := profileManifests(context.Background(), down, ps, all, fallback); ok || len(ms) != len(fallback) {
		t.Fatalf("unreachable device resolved: %v", ok)
	}
}
