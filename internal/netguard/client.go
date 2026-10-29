package netguard

import (
	"context"
	"net"
	"net/http"
	"time"
)

// NewClient is the only sanctioned way to build an outbound HTTP client: the host is checked
// against the policy before DNS, and the resolved address against the private-range rules at
// connect (redirects included). Proxies are not used. Callers set Timeout on the result.
func NewClient(p Policy) *http.Client { return NewClientWith(p, Options{}, nil) }

// NewClientWith is NewClient with explicit dialer Options (Block, Resolver, Family, Timeout) and an
// optional hook to tune the transport (TLS config, keep-alives, header timeout). The dialer is
// private-allowing when either o or p says so.
func NewClientWith(p Policy, o Options, tune func(*http.Transport)) *http.Client {
	o.AllowPrivate = o.AllowPrivate || p.AllowPrivate
	d := New(o)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if !p.HostAllowed(host) {
				return nil, &ErrEgressDenied{Host: host, Purpose: countDenied(p.Purpose)}
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	if tune != nil {
		tune(tr)
	}
	return &http.Client{Transport: tr}
}

// Guarded is the first-party client (FromEnv policy: private ranges allowed, WT_AIRGAP honoured)
// with the given overall timeout (0 = none). Redirects are followed as net/http does by default.
func Guarded(purpose string, timeout time.Duration) *http.Client {
	c := NewClient(FromEnv(purpose))
	c.Timeout = timeout
	return c
}

// GuardedNoRedirect is Guarded but returns the first response instead of following redirects.
func GuardedNoRedirect(purpose string, timeout time.Duration) *http.Client {
	c := Guarded(purpose, timeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}
