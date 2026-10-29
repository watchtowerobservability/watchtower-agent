package snmp

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func find(r *sink.Recorder, name string, kv ...string) (sink.Sample, bool) {
next:
	for _, s := range r.Samples {
		if s.Name != name {
			continue
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if s.Attrs[kv[i]] != kv[i+1] {
				continue next
			}
		}
		return s, true
	}
	return sink.Sample{}, false
}

func want(t *testing.T, r *sink.Recorder, v float64, name string, kv ...string) {
	t.Helper()
	s, ok := find(r, name, kv...)
	if !ok {
		t.Fatalf("no %s with %v in %+v", name, kv, r.Samples)
	}
	if math.Abs(s.Value-v) > 1e-6 {
		t.Fatalf("%s = %v, want %v", name, s.Value, v)
	}
}

func TestCounterWrapRate32(t *testing.T) {
	var r Rates
	t0 := time.Unix(1000, 0)
	if _, ok := r.Update("k", 4294967000, 32, t0); ok {
		t.Fatal("the first sample has no rate")
	}
	rate, ok := r.Update("k", 704, 32, t0.Add(10*time.Second)) // wrapped: 296 + 704 = 1000 in 10 s
	if !ok || rate != 100 {
		t.Fatalf("wrapped 32-bit rate = %v %v, want 100", rate, ok)
	}
	if _, ok := r.Update("k64", 5000, 64, t0); ok {
		t.Fatal("first 64-bit sample")
	}
	if _, ok := r.Update("k64", 10, 64, t0.Add(time.Second)); ok {
		t.Fatal("a 64-bit counter that went down was reset, not wrapped")
	}
	if rate, ok := r.Update("k64", 110, 64, t0.Add(2*time.Second)); !ok || rate != 100 {
		t.Fatalf("rate after reset = %v %v", rate, ok)
	}
}

func TestManifestsParseAndMatchIntegrationsDir(t *testing.T) {
	all, err := Manifests("")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"if-mib", "host-resources-mib", "entity-sensor-mib", "ups-mib", "lldp-mib"} {
		if _, ok := all[n]; !ok {
			t.Fatalf("manifest %s missing", n)
		}
	}
	ents, _ := builtinFS.ReadDir("manifests")
	for _, e := range ents {
		a, _ := builtinFS.ReadFile("manifests/" + e.Name())
		b, err := os.ReadFile("../../../integrations/snmp/" + e.Name())
		if err != nil || string(a) != string(b) {
			t.Fatalf("integrations/snmp/%s must be a copy of the embedded manifest (%v)", e.Name(), err)
		}
	}
}

func TestSNMPv2cWalkIfTable(t *testing.T) {
	f, addr := startFake(t)
	f.set(vStr("1.3.6.1.2.1.2.2.1.2.1", "eth0"))
	f.set(vStr("1.3.6.1.2.1.31.1.1.1.1.1", "eth0"))
	f.set(vTicks("1.3.6.1.2.1.1.3.0", 100000))
	f.set(vGauge("1.3.6.1.2.1.2.2.1.5.1", 1000000000))
	f.set(vInt("1.3.6.1.2.1.2.2.1.8.1", 1))
	f.set(vCounter32("1.3.6.1.2.1.2.2.1.10.1", 1000))
	f.set(vInt("1.3.6.1.2.1.2.2.1.8.2", 2))
	tg := Target{Name: "sw1", Address: addr, Community: "public", Timeout: "500ms"}

	ps, err := Walk(context.Background(), tg, []string{"1.3.6.1.2.1.2.2.1"}, 0)
	if err != nil || len(ps) != 5 {
		t.Fatalf("walk: %d varbinds, %v", len(ps), err)
	}
	if ps, err = Walk(context.Background(), tg, []string{"1.3.6.1.2.1.2.2.1"}, 2); err != nil || len(ps) != 2 {
		t.Fatalf("capped walk: %d varbinds, %v", len(ps), err)
	}

	all, _ := Manifests("")
	ms, _ := pick(all, []string{"if-mib"})
	var rates Rates
	rec := &sink.Recorder{}
	t0 := time.Unix(5000, 0)
	if err := PollTarget(context.Background(), tg, ms, &rates, rec, t0); err != nil {
		t.Fatal(err)
	}
	f.set(vCounter32("1.3.6.1.2.1.2.2.1.10.1", 6000))
	if err := PollTarget(context.Background(), tg, ms, &rates, rec, t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "snmp.device.up", "snmp.device", "sw1")
	want(t, rec, 1e9, "snmp.interface.speed", "network.interface.name", "eth0", "snmp.if_descr", "eth0", "snmp.index", "1")
	want(t, rec, 1, "snmp.interface.oper_status", "network.interface.name", "eth0")
	want(t, rec, 500, "snmp.interface.io.rate", "network.interface.name", "eth0", "network.io.direction", "receive")
	for _, s := range rec.Samples {
		for _, v := range s.Attrs {
			if strings.Contains(v, "127.0.0.1") || v == "public" {
				t.Fatalf("address or community leaked into %s: %v", s.Name, s.Attrs)
			}
		}
	}
}

func TestPollTargetDownReportsUpZeroWithoutAddress(t *testing.T) {
	tg := Target{Name: "dead", Address: "127.0.0.1:1", Community: "hunter2", Timeout: "100ms", Retries: 1}
	all, _ := Manifests("")
	ms, _ := pick(all, []string{"ups-mib"})
	rec := &sink.Recorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := PollTarget(ctx, tg, ms, &Rates{}, rec, time.Now())
	if err == nil {
		t.Fatal("polling a closed port must fail")
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks the address or community: %v", err)
	}
	want(t, rec, 0, "snmp.device.up", "snmp.device", "dead")
}

func TestSNMPv3AuthPriv(t *testing.T) {
	tg := Target{Name: "fw", Address: "192.0.2.9", Version: "3", V3: &V3{
		User: "monitor", AuthProto: "SHA256", AuthPass: "auth-pass-123", PrivProto: "AES", PrivPass: "priv-pass-456",
	}}
	if err := tg.Validate(); err != nil {
		t.Fatal(err)
	}
	g, err := tg.session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv || g.SecurityModel != gosnmp.UserSecurityModel || !ok {
		t.Fatalf("session = %+v", g)
	}
	if sp.UserName != "monitor" || sp.AuthenticationProtocol != gosnmp.SHA256 || sp.PrivacyProtocol != gosnmp.AES || g.Port != 161 {
		t.Fatalf("usm = %+v port %d", sp, g.Port)
	}
	bad := tg
	bad.V3 = &V3{User: "u", AuthProto: "sha", AuthPass: "short"}
	if bad.Validate() == nil {
		t.Fatal("a short passphrase must be refused")
	}
	bad.V3 = &V3{User: "u", PrivProto: "aes", PrivPass: "priv-pass-456"}
	if bad.Validate() == nil {
		t.Fatal("priv without auth must be refused")
	}
}

func TestScrubRemovesAddressAndSecrets(t *testing.T) {
	tg := Target{Name: "x", Address: "10.9.8.7:161", Community: "s3cret", V3: &V3{User: "bob", AuthPass: "pw-pw-pw-1"}}
	msg := tg.scrub(errors.New("dial udp 10.9.8.7:161: s3cret bob pw-pw-pw-1")).Error()
	for _, bad := range []string{"10.9.8.7", "s3cret", "bob", "pw-pw-pw-1"} {
		if strings.Contains(msg, bad) {
			t.Fatalf("%q leaked in %q", bad, msg)
		}
	}
}

func pdu(oid string, typ gosnmp.Asn1BER, v any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: "." + oid, Type: typ, Value: v}
}

func TestUPSMIBBatteryMetrics(t *testing.T) {
	all, _ := Manifests("")
	ms, _ := pick(all, []string{"ups-mib"})
	pdus := []gosnmp.SnmpPDU{
		pdu("1.3.6.1.2.1.33.1.2.1.0", gosnmp.Integer, 2),
		pdu("1.3.6.1.2.1.33.1.2.3.0", gosnmp.Integer, 30),
		pdu("1.3.6.1.2.1.33.1.2.4.0", gosnmp.Integer, 80),
		pdu("1.3.6.1.2.1.33.1.2.5.0", gosnmp.Integer, 1356),
		pdu("1.3.6.1.2.1.33.1.4.4.1.4.1", gosnmp.Integer, 250),
		pdu("1.3.6.1.2.1.33.1.4.4.1.3.1", gosnmp.Integer, 12),
	}
	rec := &sink.Recorder{}
	emit(rec, &Rates{}, "ups1", ms, pdus, time.Now())
	want(t, rec, 2, "hw.battery.status", "snmp.device", "ups1")
	want(t, rec, 1800, "hw.battery.time_left")
	want(t, rec, 0.8, "hw.battery.charge")
	want(t, rec, 135.6, "hw.battery.voltage")
	want(t, rec, 250, "hw.power", "hw.line", "1", "hw.power.direction", "output")
	want(t, rec, 1.2, "hw.ups.output.current", "hw.line", "1")
}

func TestEntitySensorMIB(t *testing.T) {
	all, _ := Manifests("")
	ms, _ := pick(all, []string{"entity-sensor-mib"})
	tb := "1.3.6.1.2.1.99.1.1.1."
	pdus := []gosnmp.SnmpPDU{
		pdu(tb+"1.5", gosnmp.Integer, 8), pdu(tb+"2.5", gosnmp.Integer, 9), pdu(tb+"3.5", gosnmp.Integer, 1),
		pdu(tb+"4.5", gosnmp.Integer, 253), pdu(tb+"5.5", gosnmp.Integer, 1),
		pdu("1.3.6.1.2.1.47.1.1.1.1.7.5", gosnmp.OctetString, []byte("CPU Inlet")),
		pdu(tb+"1.6", gosnmp.Integer, 10), pdu(tb+"2.6", gosnmp.Integer, 9), pdu(tb+"3.6", gosnmp.Integer, 0),
		pdu(tb+"4.6", gosnmp.Integer, 4200), pdu(tb+"5.6", gosnmp.Integer, 2), // broken sensor: skipped
	}
	rec := &sink.Recorder{}
	emit(rec, &Rates{}, "sw1", ms, pdus, time.Now())
	want(t, rec, 25.3, "hw.temperature", "hw.name", "CPU Inlet", "hw.type", "temperature")
	if _, ok := find(rec, "hw.fan.speed"); ok {
		t.Fatal("a sensor whose operStatus is not ok must not be reported")
	}
}

func TestHostResourcesStorageBytes(t *testing.T) {
	all, _ := Manifests("")
	ms, _ := pick(all, []string{"host-resources-mib"})
	tb := "1.3.6.1.2.1.25.2.3.1."
	pdus := []gosnmp.SnmpPDU{
		pdu(tb+"3.1", gosnmp.OctetString, []byte("/")), pdu(tb+"4.1", gosnmp.Integer, 4096),
		pdu(tb+"5.1", gosnmp.Integer, 1000), pdu(tb+"6.1", gosnmp.Integer, 250),
	}
	rec := &sink.Recorder{}
	emit(rec, &Rates{}, "srv", ms, pdus, time.Now())
	want(t, rec, 4096000, "snmp.storage.size", "hw.name", "/")
	want(t, rec, 1024000, "snmp.storage.used", "hw.name", "/")
}
