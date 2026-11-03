package snmp

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func portPDUs(in, out uint64) []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.2.2.1.8.3", Type: gosnmp.Integer, Value: 1},
		{Name: ".1.3.6.1.2.1.2.2.1.8.12", Type: gosnmp.Integer, Value: 2},
		{Name: ".1.3.6.1.2.1.31.1.1.1.1.3", Type: gosnmp.OctetString, Value: []byte("Gi1/0/7")},
		{Name: ".1.3.6.1.2.1.31.1.1.1.6.3", Type: gosnmp.Counter64, Value: in},
		{Name: ".1.3.6.1.2.1.31.1.1.1.10.3", Type: gosnmp.Counter64, Value: out},
		{Name: ".1.3.6.1.2.1.31.1.1.1.15.3", Type: gosnmp.Gauge32, Value: uint(1000)},
		// LLDP local port 7 is named Gi1/0/7, which is ifIndex 3
		{Name: ".1.0.8802.1.1.2.1.3.7.1.3.7", Type: gosnmp.OctetString, Value: []byte("gi1/0/7")},
	}
}

func TestLinkStatusAndUtilisation(t *testing.T) {
	var lr LinkRates
	t0 := time.Unix(1_000, 0)
	first := lr.States("sw1", portPDUs(0, 0), t0)
	if first["lldp:7"].Oper != "up" || first["lldp:7"].HasUtil || first["12"].Oper != "down" {
		t.Fatalf("first poll: %+v", first)
	}
	// 10 s later: 1.25e9 bytes out = 1 Gbit/s on a 1000 Mbit/s port, inbound half of that
	second := lr.States("sw1", portPDUs(625_000_000, 1_250_000_000), t0.Add(10*time.Second))
	st := second["lldp:7"]
	if !st.HasUtil || st.Util < 0.99 || st.Util > 1 {
		t.Fatalf("second poll: %+v", st)
	}
	// a counter reset gives no rate instead of a huge one
	if third := lr.States("sw1", portPDUs(1, 1), t0.Add(20*time.Second)); third["3"].HasUtil {
		t.Fatalf("reset: %+v", third["3"])
	}
	var rec sink.Recorder
	ns := []Neighbor{
		{Kind: "lldp", LocalPort: "7", Remote: Device{ID: "aa", Name: "edge"}},
		{Kind: "cdp", LocalPort: "12", Remote: Device{ID: "r3", Name: "r3"}},
		{Kind: "lldp", LocalPort: "40", Remote: Device{ID: "bb", Name: "far"}},
	}
	EmitLinks(&rec, Device{ID: "sw1", Name: "sw1"}, ns, second, t0)
	got := map[string][2]string{}
	for _, s := range rec.Samples {
		got[s.Attrs["link.remote_id"]] = [2]string{s.Attrs["link.oper_status"], s.Attrs["link.utilization"]}
	}
	if got["aa"] != [2]string{"up", "1.0000"} || got["r3"] != [2]string{"down", ""} || got["bb"] != [2]string{"", ""} {
		t.Fatalf("%v", got)
	}
}
