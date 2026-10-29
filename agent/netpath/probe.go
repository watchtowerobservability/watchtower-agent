package netpath

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const probeWait = time.Second

// SocketProber probes IPv4 with TCP SYN or UDP datagrams whose TTL is set per socket. Routers
// answer with ICMP Time Exceeded, which is read on a raw ICMP socket (CAP_NET_RAW or root).
type SocketProber struct {
	Proto string // ProtoTCP or ProtoUDP
	Dst   netip.AddrPort
}

// Probe implements Prober. A TCP probe reaches the destination when the handshake completes or
// is refused (an RST is an answer); a UDP probe when the destination returns port unreachable.
func (s SocketProber) Probe(ctx context.Context, ttl int, srcPort uint16) Result {
	raw, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return Result{}
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	start := time.Now()
	direct := make(chan bool, 1) // the destination answered on the probe's own socket
	go func() { direct <- s.send(ctx, ttl, srcPort) }()
	icmpRes := make(chan Result, 1)
	go func() { icmpRes <- s.readICMP(ctx, raw, srcPort) }()
	select {
	case ok := <-direct:
		if ok {
			return Result{Addr: s.Dst.Addr(), RTT: time.Since(start), Reached: true}
		}
		select { // not reached directly: a router may still have answered
		case r := <-icmpRes:
			r.RTT = time.Since(start)
			return r
		case <-ctx.Done():
			return Result{}
		}
	case r := <-icmpRes:
		r.RTT = time.Since(start)
		return r
	}
}

// send fires the probe; true means the destination answered on the socket itself.
func (s SocketProber) send(ctx context.Context, ttl int, srcPort uint16) bool {
	d := net.Dialer{LocalAddr: &net.TCPAddr{Port: int(srcPort)}, Control: ttlControl(ttl)}
	if s.Proto == ProtoUDP {
		d.LocalAddr = &net.UDPAddr{Port: int(srcPort)}
		c, err := d.DialContext(ctx, "udp4", s.Dst.String())
		if err == nil {
			_, _ = c.Write([]byte{0})
			c.Close()
		}
		return false // a UDP destination answers by ICMP, read separately
	}
	c, err := d.DialContext(ctx, "tcp4", s.Dst.String())
	if err == nil {
		c.Close()
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused")
}

func (s SocketProber) readICMP(ctx context.Context, raw *icmp.PacketConn, srcPort uint16) Result {
	dl, _ := ctx.Deadline()
	_ = raw.SetReadDeadline(dl)
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, peer, err := raw.ReadFrom(buf)
		if err != nil {
			return Result{}
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		var data []byte
		switch b := m.Body.(type) {
		case *icmp.TimeExceeded:
			data = b.Data
		case *icmp.DstUnreach:
			data = b.Data
		default:
			continue
		}
		if !quotedSrcPort(data, s.Proto, srcPort) {
			continue
		}
		ip, _ := netip.AddrFromSlice(peer.(*net.IPAddr).IP)
		ip = ip.Unmap()
		return Result{Addr: ip, Reached: m.Type == ipv4.ICMPTypeDestinationUnreachable && ip == s.Dst.Addr()}
	}
	return Result{}
}

// quotedSrcPort reports whether the datagram an ICMP error quotes is our probe: IPv4, the right
// protocol and our source port (the first 2 bytes of the TCP or UDP header).
func quotedSrcPort(d []byte, proto string, srcPort uint16) bool {
	want := byte(6)
	if proto == ProtoUDP {
		want = 17
	}
	if len(d) < 20 {
		return false
	}
	ihl := int(d[0]&0x0f) * 4
	if d[0]>>4 != 4 || ihl < 20 || len(d) < ihl+4 || d[9] != want {
		return false
	}
	return binary.BigEndian.Uint16(d[ihl:]) == srcPort
}
