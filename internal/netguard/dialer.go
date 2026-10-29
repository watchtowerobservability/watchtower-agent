// Package netguard keeps probes and webhook senders away from private networks (SSRF).
//
// The check runs in the dialer's Control hook, on the IP address the kernel is about to connect
// to, after DNS resolution and for every connection attempt. A name that resolves to a public
// address at one moment and a private one the next (DNS rebinding) is refused on the second
// connection, and so is a redirect to a private host: there is no separate validate-then-connect
// step to race. Redirect targets and proxies go through the same dialer, so callers must not
// configure an HTTP proxy.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlocked is returned (wrapped) when a connection target is not allowed.
var ErrBlocked = errors.New("target address is not allowed")

// BlockedError says which address was refused; it matches ErrBlocked with errors.Is.
type BlockedError struct{ Addr netip.Addr }

func (e *BlockedError) Error() string        { return fmt.Sprintf("%v: %s", ErrBlocked, e.Addr) }
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// private is address space that only a private probe may reach.
var private = prefixes(
	"::/96", "2001::/32", "64:ff9b:1::/48", "fec0::/10", // v4-compatible, Teredo, NAT64 local use, site-local
	"0.0.0.0/8",      // "this" network
	"10.0.0.0/8",     // RFC 1918
	"100.64.0.0/10",  // CGNAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, including the 169.254.169.254 metadata service
	"172.16.0.0/12",  // RFC 1918
	"192.0.0.0/24",   // IETF protocol assignments
	"192.168.0.0/16", // RFC 1918
	"198.18.0.0/15",  // benchmarking
	"::1/128",        // loopback
	"fc00::/7",       // unique local, including fd00:ec2::254
	"fe80::/10",      // link-local
)

// never is never reachable, not even by a private probe: not a unicast destination, or a cloud
// metadata endpoint that hands out credentials.
var never = prefixes(
	"0.0.0.0/32",
	"169.254.169.254/32",
	"224.0.0.0/3", // multicast and reserved, includes 255.255.255.255
	"::/128",
	"ff00::/8",
	"fd00:ec2::254/128",
)

// embedded v4 inside v6 forms that route to the v4 address.
var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
)

// Blocked reports whether ip may not be connected to. With allowPrivate (private probes), only
// the never-reachable ranges are refused.
func Blocked(ip netip.Addr, allowPrivate bool) bool {
	ip = ip.Unmap()
	switch {
	case ip.Is6() && nat64.Contains(ip):
		b := ip.As16()
		return Blocked(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), allowPrivate)
	case ip.Is6() && sixTo4.Contains(ip):
		b := ip.As16()
		return Blocked(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), allowPrivate)
	}
	for _, p := range never {
		if p.Contains(ip) {
			return true
		}
	}
	if allowPrivate {
		return false
	}
	for _, p := range private {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Options configure a guarded dialer. The zero value is a public-only dialer.
type Options struct {
	// AllowPrivate lets a private probe reach private address space.
	AllowPrivate bool
	// Block replaces the address policy (tests use it to make local listeners "public").
	Block func(netip.Addr) bool
	// Resolver replaces the system resolver (tests).
	Resolver *net.Resolver
	// Timeout bounds one connection attempt (default 10 s).
	Timeout time.Duration
	// Family "ipv4" or "ipv6" restricts connections to that family; the dialer's happy-eyeballs
	// still tries the other family first if the resolver lists it, and the attempt is refused.
	Family string
}

// DefaultFamily is the Family of SafeDialer; a private probe sets it once at startup from its
// location's prefer_ip_family. shortcut: process-wide, set before the first dial; per-location
// families need a dialer per engine.
var DefaultFamily string

// New returns a dialer whose Control hook refuses blocked addresses.
func New(o Options) *net.Dialer {
	block := o.Block
	if block == nil {
		block = func(ip netip.Addr) bool { return Blocked(ip, o.AllowPrivate) }
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	return &net.Dialer{
		Timeout:  o.Timeout,
		Resolver: o.Resolver,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: cannot parse %q", ErrBlocked, address)
			}
			if block(ap.Addr()) {
				return &BlockedError{Addr: ap.Addr().Unmap()}
			}
			if a := ap.Addr().Unmap(); o.Family == "ipv6" && a.Is4() || o.Family == "ipv4" && !a.Is4() {
				return fmt.Errorf("address family not allowed by prefer_ip_family=%s: %s", o.Family, a)
			}
			return nil
		},
	}
}

// SafeDialer is the dialer for public probe locations (allowPrivate false) and for private
// probes (true).
func SafeDialer(allowPrivate bool) *net.Dialer {
	return New(Options{AllowPrivate: allowPrivate, Family: DefaultFamily})
}

// DialContext is a convenience for http.Transport.
func DialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialContext
}
