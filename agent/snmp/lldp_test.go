package snmp

import (
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func lldpPDU(name string, v any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString, Value: v}
}

func TestLLDPNeighborsToLinks(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		lldpPDU(".1.0.8802.1.1.2.1.3.2.0", []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
		lldpPDU(".1.0.8802.1.1.2.1.3.3.0", []byte("core-sw1")),
		// lldpRemTable row: timeMark 0, local port 7, index 1
		lldpPDU(".1.0.8802.1.1.2.1.4.1.1.5.0.7.1", []byte{0xaa, 0xbb, 0xcc, 0, 1, 2}),
		lldpPDU(".1.0.8802.1.1.2.1.4.1.1.7.0.7.1", []byte("Gi1/0/24")),
		lldpPDU(".1.0.8802.1.1.2.1.4.1.1.9.0.7.1", []byte("edge-sw2")),
		// a neighbour with no system name is named by its chassis id
		lldpPDU(".1.0.8802.1.1.2.1.4.1.1.5.0.9.1", []byte{0xde, 0xad, 0xbe, 0xef, 0, 1}),
		// CDP: ifIndex 12, device index 1, with a management address
		lldpPDU(".1.3.6.1.4.1.9.9.23.1.2.1.1.4.12.1", []byte{10, 0, 0, 9}),
		lldpPDU(".1.3.6.1.4.1.9.9.23.1.2.1.1.6.12.1", []byte("Router3")),
		lldpPDU(".1.3.6.1.4.1.9.9.23.1.2.1.1.7.12.1", []byte("Gi0/1")),
		lldpPDU(".1.3.6.1.2.1.1.5.0", []byte("ignored")),
	}
	var rec sink.Recorder
	EmitNeighbors(&rec, LocalDevice(pdus, "sw1-target"), ParseNeighbors(pdus), time.Now())
	if len(rec.Samples) != 3 {
		t.Fatalf("records: %+v", rec.Samples)
	}
	want := map[string][2]string{ // kind|local port|remote id -> remote port, remote addr
		"cdp|12|router3":           {"Gi0/1", "10.0.0.9"},
		"lldp|7|aa:bb:cc:00:01:02": {"Gi1/0/24", ""},
		"lldp|9|de:ad:be:ef:00:01": {"", ""},
	}
	for _, s := range rec.Samples {
		a := s.Attrs
		k := a["link.kind"] + "|" + a["link.local_port"] + "|" + a["link.remote_id"]
		w, ok := want[k]
		if !ok || w[0] != a["link.remote_port"] || w[1] != a["link.remote_addr"] ||
			a["link.local"] != "core-sw1" || a["link.local_id"] != "00:11:22:33:44:55" ||
			a["event.name"] != "network.neighbor" {
			t.Fatalf("unexpected record %s: %v", k, a)
		}
		delete(want, k)
	}
	if len(want) != 0 {
		t.Fatalf("missing: %v", want)
	}
}

func TestLocalDeviceFallsBackToTargetName(t *testing.T) {
	d := LocalDevice(nil, "Lab-SW")
	if d.ID != "lab-sw" || d.Name != "Lab-SW" || strings.Contains(d.Addr, ".") {
		t.Fatalf("%+v", d)
	}
}
