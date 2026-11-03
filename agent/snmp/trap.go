package snmp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	defaultMaxPacket = 4096
	maxVarbindsInLog = 64
	snmpTrapOID      = "1.3.6.1.6.3.1.1.4.1.0"
)

// TrapConfig configures the trap receiver. Communities and users are local-file only.
type TrapConfig struct {
	Listen      string            `json:"listen"`      // default 0.0.0.0:162
	Communities []string          `json:"communities"` // accepted for v1 and v2c; others are dropped
	V3          []V3              `json:"v3"`          // accepted v3 users; others are dropped
	Sources     map[string]string `json:"sources"`     // sender IP -> device name (snmp.device)
	MaxPacket   int               `json:"max_packet"`  // bytes; larger datagrams are dropped (default 4096)
	// RatePerSource is the most traps per second accepted from one sender IP (default 100);
	// the excess is dropped and counted as "rate".
	RatePerSource int `json:"rate_per_source"`
	// ProfileDir holds extra per-vendor trap profiles (*.yaml, e.g. from `wtctl mib compile`).
	ProfileDir string `json:"profile_dir"`
}

type bucket struct {
	tokens float64
	at     time.Time
}

// allow is a token bucket per sender IP: rate tokens per second, burst of one second.
func (l *Listener) allow(ip string, now time.Time) bool {
	rate := float64(l.cfg.RatePerSource)
	if rate <= 0 {
		rate = 100
	}
	if len(l.buckets) > 10000 { // spoofed sources must not grow the map without bound
		l.buckets = map[string]*bucket{}
	}
	b := l.buckets[ip]
	if b == nil {
		b = &bucket{tokens: rate, at: now}
		l.buckets[ip] = b
	}
	b.tokens = min(rate, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Listener receives traps over UDP and writes each as an OTLP log record.
type Listener struct {
	cfg  TrapConfig
	out  sink.Sink
	comm map[string]bool
	x    *gosnmp.GoSNMP
	conn *net.UDPConn
	max  int

	buckets  map[string]*bucket // only touched by the Serve goroutine
	profiles TrapProfiles

	received, dropCommunity, dropDecode, dropSize, dropRate atomic.Int64
}

// NewListener validates the config. Call Listen, then Serve.
func NewListener(c TrapConfig, out sink.Sink) (*Listener, error) {
	l := &Listener{cfg: c, out: out, comm: map[string]bool{}, max: c.MaxPacket, buckets: map[string]*bucket{}}
	if l.max <= 0 {
		l.max = defaultMaxPacket
	}
	if l.max > 65507 {
		return nil, errors.New("trap max_packet is above the UDP limit")
	}
	ps, err := LoadTrapProfiles(c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("trap profiles: %w", err)
	}
	l.profiles = ps
	for _, s := range c.Communities {
		if s != "" {
			l.comm[s] = true
		}
	}
	lg := gosnmp.NewLogger(log.New(io.Discard, "", 0))
	l.x = &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: lg}
	if len(c.V3) > 0 {
		tbl := gosnmp.NewSnmpV3SecurityParametersTable(lg)
		for i, u := range c.V3 {
			sp, flags, err := u.usm()
			if err != nil {
				return nil, fmt.Errorf("trap v3 user %d: %w", i, err)
			}
			// The sender is the authoritative engine of a trap: its keys are localized with
			// the sender's engine ID, so a trap user cannot work without it.
			eid, err := hex.DecodeString(u.EngineID)
			if err != nil || len(eid) < 5 || len(eid) > 32 {
				return nil, fmt.Errorf("trap v3 user %d: engine_id must be 5 to 32 bytes of hex", i)
			}
			sp.AuthoritativeEngineID = string(eid)
			if err := tbl.Add(u.User, sp); err != nil {
				return nil, fmt.Errorf("trap v3 user %d: %w", i, err)
			}
			if i == 0 {
				l.x.SecurityModel, l.x.MsgFlags, l.x.SecurityParameters = gosnmp.UserSecurityModel, flags, sp
			}
		}
		l.x.TrapSecurityParametersTable = tbl
		l.x.Version = gosnmp.Version3 // gosnmp's v3 trap authentication refuses any other connection version
	}
	return l, nil
}

// Listen binds the UDP socket.
func (l *Listener) Listen() error {
	addr, err := net.ResolveUDPAddr("udp", orDefault(l.cfg.Listen, "0.0.0.0:162"))
	if err != nil {
		return err
	}
	l.conn, err = net.ListenUDP("udp", addr)
	return err
}

// Addr is the bound address (after Listen).
func (l *Listener) Addr() net.Addr { return l.conn.LocalAddr() }

// Dropped counts the traps rejected for a reason: "community", "decode" (unknown v3 user, bad
// authentication or a malformed packet) or "size".
func (l *Listener) Dropped(reason string) int64 {
	switch reason {
	case "community":
		return l.dropCommunity.Load()
	case "decode":
		return l.dropDecode.Load()
	case "size":
		return l.dropSize.Load()
	case "rate":
		return l.dropRate.Load()
	}
	return 0
}

// Report writes the receiver's cumulative counters.
func (l *Listener) Report(at time.Time) {
	l.out.Sum("snmp.trap.received", "{trap}", float64(l.received.Load()), nil, at)
	for _, r := range []string{"community", "decode", "size", "rate"} {
		l.out.Sum("snmp.trap.dropped", "{trap}", float64(l.Dropped(r)), map[string]string{"snmp.trap.drop_reason": r}, at)
	}
}

// Serve reads traps until ctx ends.
func (l *Listener) Serve(ctx context.Context) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.conn.Close()
		case <-done:
		}
	}()
	buf := make([]byte, l.max+1) // one spare byte tells a datagram that was too big
	for {
		n, from, err := l.conn.ReadFromUDP(buf)
		if err != nil && n == len(buf) {
			// Windows reports a datagram larger than buf as an error (WSAEMSGSIZE) with buf filled.
			l.handle(buf[:n], from)
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		l.handle(buf[:n], from)
	}
}

// peekVersion reads the SNMP version (0 v1, 1 v2c, 3 v3) from the BER header; -1 if malformed.
func peekVersion(b []byte) int {
	if len(b) < 5 || b[0] != 0x30 {
		return -1
	}
	off := 2
	if b[1] >= 0x80 {
		off += int(b[1] & 0x7f)
	}
	if off+2 >= len(b) || b[off] != 0x02 || b[off+1] != 1 {
		return -1
	}
	return int(b[off+2])
}

// skipTLV returns the offset after the TLV that starts at off, or -1.
func skipTLV(b []byte, off int) int {
	if off+2 > len(b) {
		return -1
	}
	n, hl := int(b[off+1]), 2
	if b[off+1] >= 0x80 {
		k := int(b[off+1] & 0x7f)
		if k == 0 || k > 3 || off+2+k > len(b) {
			return -1
		}
		n = 0
		for _, c := range b[off+2 : off+2+k] {
			n = n<<8 | int(c)
		}
		hl += k
	}
	if off+hl+n > len(b) {
		return -1
	}
	return off + hl + n
}

// ackV2c answers a v2c InformRequest: the same message with the PDU type changed to
// GetResponse (RFC 3416: the response repeats the request id and varbinds, error 0).
func ackV2c(pkt []byte) []byte {
	if len(pkt) < 5 || pkt[0] != 0x30 {
		return nil
	}
	off := 2
	if pkt[1] >= 0x80 {
		off += int(pkt[1] & 0x7f)
	}
	for range 2 { // version, community
		if off = skipTLV(pkt, off); off < 0 {
			return nil
		}
	}
	if off >= len(pkt) || pkt[off] != 0xa6 {
		return nil
	}
	ack := append([]byte(nil), pkt...)
	ack[off] = 0xa2
	return ack
}

func (l *Listener) handle(pkt []byte, from *net.UDPAddr) {
	if len(pkt) > l.max {
		l.dropSize.Add(1)
		return
	}
	if from != nil && !l.allow(from.IP.String(), time.Now()) {
		l.dropRate.Add(1)
		return
	}
	if v := peekVersion(pkt); v < 0 || v > 3 || v == 2 || v == 3 && l.x.TrapSecurityParametersTable == nil {
		l.dropDecode.Add(1)
		return
	}
	sp, err := l.unmarshal(pkt)
	if err != nil {
		l.dropDecode.Add(1)
		return
	}
	if sp.Version != gosnmp.Version3 && !l.comm[sp.Community] {
		l.dropCommunity.Add(1)
		return
	}
	l.received.Add(1)
	// Informs ask for an answer; without one the sender retransmits. v3 informs would need this
	// agent to act as an authoritative engine, so only v1/v2c are acknowledged.
	if sp.PDUType == gosnmp.InformRequest && sp.Version == gosnmp.Version2c && from != nil {
		if ack := ackV2c(pkt); ack != nil {
			_, _ = l.conn.WriteToUDP(ack, from)
		}
	}
	oid := trapOID(sp)
	sev, body := severity(oid), "SNMP trap "+oid
	if p, ok := l.profiles[oid]; ok {
		body = "SNMP trap " + p.Name
		if p.Severity != "" {
			sev = p.Severity
		}
	}
	l.out.Log(sev, body, l.attrs(sp, from), time.Now())
}

// unmarshal decodes one packet; a panic on hostile input becomes an error.
func (l *Listener) unmarshal(b []byte) (p *gosnmp.SnmpPacket, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed trap: %v", r)
		}
	}()
	return l.x.UnmarshalTrap(b, false)
}

func (l *Listener) attrs(p *gosnmp.SnmpPacket, from *net.UDPAddr) map[string]string {
	a := map[string]string{"snmp.trap.oid": trapOID(p), "snmp.trap.version": versionName(p.Version)}
	prof, hasProf := l.profiles[a["snmp.trap.oid"]]
	if n := TrapName(a["snmp.trap.oid"]); n != "" {
		a["snmp.trap.name"] = n
	}
	if hasProf {
		a["snmp.trap.name"], a["snmp.trap.vendor"] = prof.Name, prof.Vendor
	}
	if from != nil {
		if name := l.cfg.Sources[from.IP.String()]; name != "" {
			a["snmp.device"] = name
		}
	}
	for i, v := range p.Variables {
		if i >= maxVarbindsInLog {
			a["snmp.varbinds.truncated"] = "true"
			break
		}
		a["snmp.varbind."+norm(v.Name)] = sink.Truncate(pduString(v), 512)
		if vb, ok := prof.varbind(v.Name); hasProf && ok {
			a["snmp.var."+vb.Name] = sink.Truncate(vb.Label(pduString(v)), 512)
		}
	}
	return a
}

func versionName(v gosnmp.SnmpVersion) string {
	switch v {
	case gosnmp.Version1:
		return "1"
	case gosnmp.Version3:
		return "3"
	}
	return "2c"
}

// trapOID names the trap: snmpTrapOID.0 for v2c/v3; for v1 the RFC 3584 translation.
func trapOID(p *gosnmp.SnmpPacket) string {
	if p.Version == gosnmp.Version1 {
		if p.GenericTrap == 6 {
			return norm(p.Enterprise) + ".0." + strconv.Itoa(p.SpecificTrap)
		}
		return "1.3.6.1.6.3.1.1.5." + strconv.Itoa(p.GenericTrap+1)
	}
	for _, v := range p.Variables {
		if norm(v.Name) == snmpTrapOID {
			return norm(pduString(v))
		}
	}
	return "unknown"
}

// severity: cold/warm start and link up are informational, everything else a warning.
func severity(oid string) string {
	switch oid {
	case "1.3.6.1.6.3.1.1.5.1", "1.3.6.1.6.3.1.1.5.2", "1.3.6.1.6.3.1.1.5.4":
		return "INFO"
	}
	return "WARN"
}
