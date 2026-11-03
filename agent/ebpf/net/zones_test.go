package net

import "testing"

func TestZonesTagEdges(t *testing.T) {
	z := NewZones("eu-1a", []ZonePrefix{{"10.0.0.0/8", "eu-1a"}, {"10.1.0.0/16", "eu-1b"}, {"nonsense", "x"}})
	a := map[string]string{}
	z.tag(a, "10.1.2.3")
	if a["src.zone"] != "eu-1a" || a["dst.zone"] != "eu-1b" || a["net.cross_zone"] != "true" {
		t.Fatal(a)
	}
	a = map[string]string{}
	z.tag(a, "10.2.0.1")
	if a["net.cross_zone"] != "false" {
		t.Fatal(a)
	}
	a = map[string]string{}
	z.tag(a, "payments.svc")
	if _, ok := a["net.cross_zone"]; ok {
		t.Fatal("an unknown peer has no cross-zone verdict")
	}
	(*Zones)(nil).tag(a, "10.1.0.1") // nil adds nothing
}

func TestNodeZones(t *testing.T) {
	nets, err := nodeZones([]byte(`{"items":[
	 {"metadata":{"labels":{"topology.kubernetes.io/zone":"z1"}},"spec":{"podCIDRs":["10.5.0.0/24"]},"status":{"addresses":[{"type":"InternalIP","address":"192.168.0.4"},{"type":"Hostname","address":"n1"}]}},
	 {"metadata":{"labels":{}},"spec":{"podCIDRs":["10.6.0.0/24"]}}]}`))
	if err != nil || len(nets) != 2 {
		t.Fatal(nets, err)
	}
	z := NewZones("", nil)
	z.set(nets)
	if z.lookup("10.5.0.9") != "z1" || z.lookup("192.168.0.4") != "z1" || z.lookup("10.6.0.1") != "" {
		t.Fatal(z.nets)
	}
}
