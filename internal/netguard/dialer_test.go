package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBlockedRanges(t *testing.T) {
	cases := []struct {
		ip      string
		public  bool // blocked for a public probe
		private bool // blocked for a private probe
	}{
		{"127.0.0.1", true, false},
		{"::1", true, false},
		{"10.1.2.3", true, false},
		{"172.16.0.1", true, false},
		{"172.31.255.255", true, false},
		{"192.168.1.1", true, false},
		{"169.254.169.254", true, true}, // metadata: never
		{"169.254.1.1", true, false},
		{"100.64.0.1", true, false},
		{"100.127.255.255", true, false},
		{"0.0.0.1", true, false},
		{"0.0.0.0", true, true},
		{"fd00::1", true, false},
		{"fd00:ec2::254", true, true},
		{"fe80::1", true, false},
		{"::ffff:127.0.0.1", true, false}, // v4-mapped
		{"::ffff:169.254.169.254", true, true},
		{"64:ff9b::7f00:1", true, false}, // NAT64 of 127.0.0.1
		{"2002:7f00:1::", true, false},   // 6to4 of 127.0.0.1
		{"224.0.0.1", true, true},
		{"255.255.255.255", true, true},
		{"ff02::1", true, true},
		{"::", true, true},
		{"2001::1", true, false}, // Teredo
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", true, false},
		{"fec0::1", true, false},      // site-local
		{"::7f00:1", true, false},     // IPv4-compatible 127.0.0.1
		{"64:ff9b:1::1", true, false}, // NAT64 local use
		{"8.8.8.8", false, false},
		{"1.1.1.1", false, false},
		{"172.15.255.255", false, false},
		{"172.32.0.1", false, false},
		{"100.63.255.255", false, false},
		{"2606:4700::1111", false, false},
		{"64:ff9b::808:808", false, false}, // NAT64 of 8.8.8.8
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := Blocked(ip, false); got != c.public {
			t.Errorf("Blocked(%s, public) = %v, want %v", c.ip, got, c.public)
		}
		if got := Blocked(ip, true); got != c.private {
			t.Errorf("Blocked(%s, private) = %v, want %v", c.ip, got, c.private)
		}
	}
}

func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l
}

func TestDialerRefusesLoopbackLiteral(t *testing.T) {
	l := listen(t, "127.0.0.1:0")
	_, err := SafeDialer(false).DialContext(context.Background(), "tcp", l.Addr().String())
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("public dialer to loopback: %v", err)
	}
	c, err := SafeDialer(true).DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("private dialer to loopback: %v", err)
	}
	_ = c.Close()
}

// fakeDNS answers A and AAAA queries from answer(name, type); the resolver talks to it over UDP.
func fakeDNS(t *testing.T, answer func(typ dnsmessage.Type) []netip.Addr) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no UDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			q := m.Questions[0]
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: m.ID, Response: true, Authoritative: true},
				Questions: m.Questions,
			}
			for _, ip := range answer(q.Type) {
				h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}
				switch {
				case q.Type == dnsmessage.TypeA && ip.Is4():
					h.Type = dnsmessage.TypeA
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: ip.As4()}})
				case q.Type == dnsmessage.TypeAAAA && ip.Is6():
					h.Type = dnsmessage.TypeAAAA
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}})
				}
			}
			out, err := resp.Pack()
			if err == nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
}

// A name that is allowed when first resolved and private when resolved again (DNS rebinding) is
// refused on the second connection: the address is checked where the connection is made.
func TestDialerRefusesDNSRebinding(t *testing.T) {
	l4 := listen(t, "127.0.0.1:0")
	port := l4.Addr().(*net.TCPAddr).Port
	l6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("no ::1 on the port: %v", err)
	}
	var accepted6 atomic.Int32
	go func() {
		for {
			c, err := l6.Accept()
			if err != nil {
				return
			}
			accepted6.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l6.Close() })

	var rebound atomic.Bool
	res := fakeDNS(t, func(typ dnsmessage.Type) []netip.Addr {
		if rebound.Load() {
			if typ == dnsmessage.TypeAAAA {
				return []netip.Addr{netip.MustParseAddr("::1")}
			}
			return nil
		}
		if typ == dnsmessage.TypeA {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		return nil
	})
	// the test policy treats 127.0.0.1 as public and ::1 as private
	d := New(Options{Resolver: res, Timeout: 3 * time.Second, Block: func(ip netip.Addr) bool { return ip == netip.MustParseAddr("::1") }})
	addr := net.JoinHostPort("rebind.test", strconv.Itoa(port))
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("first connection (public answer): %v", err)
	}
	_ = c.Close()
	rebound.Store(true)
	if _, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrBlocked) {
		t.Fatalf("second connection (private answer): %v", err)
	}
	if n := accepted6.Load(); n != 0 {
		t.Fatalf("the private listener saw %d connections", n)
	}
}
