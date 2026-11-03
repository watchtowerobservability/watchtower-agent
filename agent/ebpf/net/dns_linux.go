//go:build linux

package net

import (
	"context"
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
)

// dnsPacket is a parsed DNS packet seen on the wire.
type dnsPacket struct {
	msg   DNSMsg
	cport uint16
	at    time.Time
}

// captureDNS reads IPv4 and IPv6 UDP port 53 traffic from every interface with cooked AF_PACKET
// sockets (needs CAP_NET_RAW, which the module's privileges include) and sends parsed packets
// to out until ctx ends. shortcut: no per-container attribution (the capture has no cgroup) and
// IPv6 extension headers are not walked; upgrade by adding a cgroup_skb program.
func captureDNS(ctx context.Context, out chan<- dnsPacket) error {
	errs := make(chan error, 2)
	for _, proto := range []uint16{unix.ETH_P_IP, unix.ETH_P_IPV6} {
		go func() { errs <- captureProto(ctx, proto, out) }()
	}
	// the first failure is reported at once; the other family keeps capturing until ctx ends
	for range 2 {
		if err := <-errs; err != nil {
			return err
		}
	}
	return nil
}

func captureProto(ctx context.Context, proto uint16, out chan<- dnsPacket) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(proto)))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		unix.Close(fd) // unblocks Recvfrom
	}()
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if p, ok := parseUDP53(buf[:n]); ok {
			p.at = time.Now()
			select {
			case out <- p:
			default: // the aggregation loop is behind: drop rather than block capture
			}
		}
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// parseUDP53 extracts the DNS message from an IPv4 or IPv6 packet when it is UDP to or from port 53.
func parseUDP53(b []byte) (dnsPacket, bool) {
	var u []byte
	switch {
	case len(b) >= 28 && b[0]>>4 == 4 && b[9] == unix.IPPROTO_UDP:
		ihl := int(b[0]&0xf) * 4
		if len(b) < ihl+8 {
			return dnsPacket{}, false
		}
		u = b[ihl:]
	case len(b) >= 48 && b[0]>>4 == 6 && b[6] == unix.IPPROTO_UDP:
		u = b[40:]
	default:
		return dnsPacket{}, false
	}
	sp, dp := binary.BigEndian.Uint16(u[0:2]), binary.BigEndian.Uint16(u[2:4])
	var cport uint16
	switch {
	case dp == 53:
		cport = sp
	case sp == 53:
		cport = dp
	default:
		return dnsPacket{}, false
	}
	m, ok := ParseDNS(u[8:])
	return dnsPacket{msg: m, cport: cport}, ok
}
