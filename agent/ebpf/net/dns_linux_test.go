//go:build linux

package net

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseUDP53ReadsIPv6(t *testing.T) {
	dns := dnsPacketBytes(t, 9, false, 0)
	pkt := make([]byte, 40+8+len(dns))
	pkt[0] = 6 << 4
	pkt[6] = unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(pkt[40:], 40000)
	binary.BigEndian.PutUint16(pkt[42:], 53)
	copy(pkt[48:], dns)
	p, ok := parseUDP53(pkt)
	if !ok || p.cport != 40000 {
		t.Fatalf("ipv6 packet not parsed: %+v %v", p, ok)
	}
	pkt[6] = unix.IPPROTO_TCP
	if _, ok := parseUDP53(pkt); ok {
		t.Fatal("TCP must not parse as DNS over UDP")
	}
}
