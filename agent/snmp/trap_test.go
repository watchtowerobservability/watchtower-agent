package snmp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// logSink hands log records to a channel so tests can wait for them.
type logSink struct{ ch chan sink.Sample }

func (logSink) Gauge(string, string, float64, map[string]string, time.Time) {}
func (logSink) Sum(string, string, float64, map[string]string, time.Time)   {}
func (l logSink) Log(sev, body string, a map[string]string, _ time.Time) {
	l.ch <- sink.Sample{Sev: sev, Body: body, Attrs: a}
}

func startListener(t *testing.T, c TrapConfig) (*Listener, logSink) {
	t.Helper()
	c.Listen = "127.0.0.1:0"
	out := logSink{make(chan sink.Sample, 16)}
	l, err := NewListener(c, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = l.Serve(ctx) }()
	return l, out
}

func sendTrap(t *testing.T, to net.Addr, community string, vars ...gosnmp.SnmpPDU) {
	t.Helper()
	g := &gosnmp.GoSNMP{
		Target: "127.0.0.1", Port: uint16(to.(*net.UDPAddr).Port), Version: gosnmp.Version2c,
		Community: community, Timeout: time.Second,
	}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(gosnmp.SnmpTrap{Variables: vars}); err != nil {
		t.Fatal(err)
	}
}

func linkDown() []gosnmp.SnmpPDU {
	return []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1000)},
		{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		{Name: ".1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},
		{Name: ".1.3.6.1.2.1.2.2.1.2.3", Type: gosnmp.OctetString, Value: []byte("ge-0/0/3")},
	}
}

func recv(t *testing.T, out logSink) sink.Sample {
	t.Helper()
	select {
	case s := <-out.ch:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("no trap log arrived")
		return sink.Sample{}
	}
}

func TestTrapV2cBecomesLog(t *testing.T) {
	l, out := startListener(t, TrapConfig{Communities: []string{"public"}, Sources: map[string]string{"127.0.0.1": "core-sw"}})
	sendTrap(t, l.Addr(), "public", linkDown()...)
	s := recv(t, out)
	if s.Sev != "WARN" || s.Attrs["snmp.trap.oid"] != "1.3.6.1.6.3.1.1.5.3" || s.Attrs["snmp.trap.version"] != "2c" {
		t.Fatalf("trap log = %+v", s)
	}
	if s.Attrs["snmp.varbind.1.3.6.1.2.1.2.2.1.2.3"] != "ge-0/0/3" || s.Attrs["snmp.varbind.1.3.6.1.2.1.2.2.1.1.3"] != "3" {
		t.Fatalf("varbinds = %+v", s.Attrs)
	}
	if s.Attrs["snmp.device"] != "core-sw" {
		t.Fatalf("source mapping: %+v", s.Attrs)
	}
	for k, v := range s.Attrs {
		if v == "public" {
			t.Fatalf("community leaked in %s", k)
		}
	}
}

func TestTrapUnknownCommunityDropped(t *testing.T) {
	l, out := startListener(t, TrapConfig{Communities: []string{"public"}})
	sendTrap(t, l.Addr(), "guess", linkDown()...)
	sendTrap(t, l.Addr(), "public", linkDown()...)
	s := recv(t, out) // the first record is the accepted trap: the other was dropped
	if s.Attrs["snmp.trap.oid"] == "" {
		t.Fatalf("got %+v", s)
	}
	if l.Dropped("community") != 1 {
		t.Fatalf("dropped for community = %d, want 1", l.Dropped("community"))
	}
	select {
	case extra := <-out.ch:
		t.Fatalf("the unknown-community trap was logged: %+v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTrapOversizeAndGarbageDropped(t *testing.T) {
	l, out := startListener(t, TrapConfig{Communities: []string{"public"}, MaxPacket: 128})
	c, err := net.Dial("udp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(make([]byte, 1000))                               // bigger than max_packet
	_, _ = c.Write([]byte("not snmp at all"))                        // not BER
	_, _ = c.Write([]byte{0x30, 0x05, 0x02, 0x01, 0x03, 0x04, 0x00}) // v3 header, no v3 users configured
	deadline := time.Now().Add(2 * time.Second)
	for (l.Dropped("size") < 1 || l.Dropped("decode") < 2) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l.Dropped("size") != 1 || l.Dropped("decode") != 2 {
		t.Fatalf("size %d decode %d", l.Dropped("size"), l.Dropped("decode"))
	}
	select {
	case s := <-out.ch:
		t.Fatalf("garbage was logged: %+v", s)
	default:
	}
}

func TestTrapV1Translation(t *testing.T) {
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, SnmpTrap: gosnmp.SnmpTrap{GenericTrap: 2}}
	if got := trapOID(p); got != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("linkDown v1 = %s", got)
	}
	p = &gosnmp.SnmpPacket{Version: gosnmp.Version1, SnmpTrap: gosnmp.SnmpTrap{GenericTrap: 6, Enterprise: ".1.3.6.1.4.1.9", SpecificTrap: 7}}
	if got := trapOID(p); got != "1.3.6.1.4.1.9.0.7" {
		t.Fatalf("enterprise v1 = %s", got)
	}
}
