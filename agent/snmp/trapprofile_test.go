package snmp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestBuiltinTrapProfilesLoad(t *testing.T) {
	ps, err := LoadTrapProfiles("")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ps["1.3.6.1.4.1.9.9.41.2.0.1"]
	if !ok || p.Vendor != "cisco" || p.Name != "clogMessageGenerated" {
		t.Fatalf("%+v", p)
	}
	vb, ok := p.varbind(".1.3.6.1.4.1.9.9.41.1.2.3.1.3.17")
	if !ok || vb.Name != "clogHistSeverity" || vb.Label("4") != "error" || vb.Label("99") != "99" {
		t.Fatalf("%+v", vb)
	}
	if ps["1.3.6.1.4.1.2636.4.1.3"].Severity != "ERROR" {
		t.Fatal("juniper over-temperature should be an error")
	}
}

func TestLocalTrapProfileReplacesBuiltin(t *testing.T) {
	dir := t.TempDir()
	f := "vendor: acme\ntraps:\n  - {oid: .1.3.6.1.4.1.9.9.41.2.0.1, name: acmeLog, severity: INFO}\n"
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(f), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadTrapProfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p := ps["1.3.6.1.4.1.9.9.41.2.0.1"]; p.Name != "acmeLog" || p.Vendor != "acme" {
		t.Fatalf("%+v", p)
	}
	bad := "vendor: x\ntraps:\n  - {oid: 1.2.3, name: y, severity: LOUD}\n"
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrapProfiles(dir); err == nil {
		t.Fatal("unknown severity accepted")
	}
}

func TestVendorTrapGetsNameSeverityAndVarbindLabels(t *testing.T) {
	l, out := startListener(t, TrapConfig{Communities: []string{"public"}})
	sendTrap(t, l.Addr(), "public",
		gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)},
		gosnmp.SnmpPDU{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.9.41.2.0.1"},
		gosnmp.SnmpPDU{Name: ".1.3.6.1.4.1.9.9.41.1.2.3.1.3.5", Type: gosnmp.Integer, Value: 3},
		gosnmp.SnmpPDU{Name: ".1.3.6.1.4.1.9.9.41.1.2.3.1.5.5", Type: gosnmp.OctetString, Value: []byte("%LINK-3-UPDOWN")},
	)
	select {
	case s := <-out.ch:
		if s.Sev != "WARN" || s.Body != "SNMP trap clogMessageGenerated" {
			t.Fatalf("%s %q", s.Sev, s.Body)
		}
		if s.Attrs["snmp.trap.vendor"] != "cisco" || s.Attrs["snmp.var.clogHistSeverity"] != "critical" ||
			s.Attrs["snmp.var.clogHistMsgText"] != "%LINK-3-UPDOWN" {
			t.Fatalf("%v", s.Attrs)
		}
		if s.Attrs["snmp.varbind.1.3.6.1.4.1.9.9.41.1.2.3.1.3.5"] != "3" {
			t.Fatal("numeric varbind kept")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no trap")
	}
}
