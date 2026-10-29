package snmp

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const testEngineHex = "8000000001020304"

func v3User() V3 {
	return V3{User: "monitor", EngineID: testEngineHex, AuthProto: "sha", AuthPass: "auth-pass-123", PrivProto: "aes", PrivPass: "priv-pass-456"}
}

// sendV3Trap builds the packet with gosnmp's own v3 marshalling (authPriv, SHA, AES).
func sendV3Trap(t *testing.T, to net.Addr, authPass string) {
	t.Helper()
	eid, _ := hex.DecodeString(testEngineHex)
	g := &gosnmp.GoSNMP{
		Target: "127.0.0.1", Port: uint16(to.(*net.UDPAddr).Port), Version: gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, Timeout: time.Second,
		ContextEngineID: string(eid),
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName: "monitor", AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: authPass,
			PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-456", AuthoritativeEngineID: string(eid),
		},
	}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(gosnmp.SnmpTrap{Variables: linkDown()}); err != nil {
		t.Fatal(err)
	}
}

func TestTrapV3AuthPrivAuthenticates(t *testing.T) {
	l, out := startListener(t, TrapConfig{V3: []V3{v3User()}})
	sendV3Trap(t, l.Addr(), "wrong-auth-pass") // authentication fails: dropped, counted
	sendV3Trap(t, l.Addr(), "auth-pass-123")
	s := recv(t, out)
	if s.Attrs["snmp.trap.version"] != "3" || s.Attrs["snmp.trap.oid"] != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("v3 trap log = %+v", s)
	}
	if l.Dropped("decode") != 1 {
		t.Fatalf("decode drops = %d, want 1", l.Dropped("decode"))
	}
}

func TestTrapV3UserNeedsEngineID(t *testing.T) {
	u := v3User()
	u.EngineID = ""
	if _, err := NewListener(TrapConfig{V3: []V3{u}}, logSink{}); err == nil {
		t.Fatal("a trap user without engine_id must be refused")
	}
	u.EngineID = "zz"
	if _, err := NewListener(TrapConfig{V3: []V3{u}}, logSink{}); err == nil {
		t.Fatal("engine_id must be hex")
	}
}

func TestTrapInformAcknowledged(t *testing.T) {
	l, out := startListener(t, TrapConfig{Communities: []string{"public"}})
	g := &gosnmp.GoSNMP{
		Target: "127.0.0.1", Port: uint16(l.Addr().(*net.UDPAddr).Port), Version: gosnmp.Version2c,
		Community: "public", Timeout: time.Second, Retries: 0,
	}
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	defer g.Conn.Close()
	if _, err := g.SendTrap(gosnmp.SnmpTrap{IsInform: true, Variables: linkDown()}); err != nil {
		t.Fatalf("the inform was not acknowledged: %v", err)
	}
	if s := recv(t, out); s.Attrs["snmp.trap.oid"] != "1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("inform log = %+v", s)
	}
}

func TestAckV2cKeepsEverythingButThePDUType(t *testing.T) {
	// SEQ{ INT 1, OCTET "p", InformRequest{ INT 7, INT 0, INT 0, SEQ{} } }
	in := []byte{0x30, 0x14, 0x02, 0x01, 0x01, 0x04, 0x01, 'p', 0xa6, 0x0c, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00}
	in[1] = byte(len(in) - 2)
	in[9] = byte(len(in) - 10)
	ack := ackV2c(in)
	if ack == nil || ack[8] != 0xa2 || string(ack[:8]) != string(in[:8]) || string(ack[9:]) != string(in[9:]) {
		t.Fatalf("ack = %x", ack)
	}
	if ackV2c([]byte{0x30, 0x03, 0x02, 0x01, 0x01}) != nil {
		t.Fatal("a truncated packet has no ack")
	}
}

func TestTrapRateLimitPerSource(t *testing.T) {
	l, err := NewListener(TrapConfig{RatePerSource: 2}, logSink{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if !l.allow("10.0.0.1", now) || !l.allow("10.0.0.1", now) {
		t.Fatal("the burst of one second is allowed")
	}
	if l.allow("10.0.0.1", now) {
		t.Fatal("the third trap in the same instant must be dropped")
	}
	if !l.allow("10.0.0.2", now) {
		t.Fatal("another source has its own bucket")
	}
	if !l.allow("10.0.0.1", now.Add(time.Second)) {
		t.Fatal("tokens refill with time")
	}
}

type gaugeSink struct{ ch chan float64 }

func (g gaugeSink) Gauge(name, _ string, v float64, _ map[string]string, _ time.Time) {
	if name == trapUp {
		select {
		case g.ch <- v:
		default:
		}
	}
}
func (gaugeSink) Sum(string, string, float64, map[string]string, time.Time) {}
func (gaugeSink) Log(string, string, map[string]string, time.Time)          {}

func TestTrapBindFailureIsReportedAndRetried(t *testing.T) {
	old := trapRetry
	trapRetry = 20 * time.Millisecond
	t.Cleanup(func() { trapRetry = old })
	occupant, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer occupant.Close()
	gs := gaugeSink{make(chan float64, 64)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		trapLoop(ctx, TrapConfig{Listen: occupant.LocalAddr().String(), Communities: []string{"public"}}, gs)
		close(done)
	}()
	select {
	case v := <-gs.ch:
		if v != 0 {
			t.Fatalf("listener_up = %v while the port is taken", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no listener_up gauge")
	}
	occupant.Close() // the port frees up: the next retry binds
	deadline := time.After(3 * time.Second)
	for up := false; !up; {
		select {
		case v := <-gs.ch:
			up = v == 1
		case <-deadline:
			t.Fatal("the listener never came up after the port was freed")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("trapLoop did not stop")
	}
}

var _ sink.Sink = logSink{}
