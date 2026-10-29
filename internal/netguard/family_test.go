package netguard

import (
	"context"
	"net"
	"testing"
)

func TestPreferIPv6Dials(t *testing.T) {
	l6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	defer l6.Close()
	l4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l4.Close()
	d := New(Options{AllowPrivate: true, Family: "ipv6"})
	c, err := d.DialContext(context.Background(), "tcp", l6.Addr().String())
	if err != nil {
		t.Fatalf("ipv6 refused: %v", err)
	}
	c.Close()
	if c, err := d.DialContext(context.Background(), "tcp", l4.Addr().String()); err == nil {
		c.Close()
		t.Fatal("ipv4 dialed under ipv6 preference")
	}
}
