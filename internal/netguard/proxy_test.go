package netguard

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func proxyClient(t *testing.T, o Options) *http.Client {
	t.Helper()
	p, err := NewProxy(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	u, _ := url.Parse(p.URL())
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

func TestProxyRefusesPrivateTargets(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) }))
	defer backend.Close()
	// a public-only proxy refuses the loopback backend and the metadata address
	c := proxyClient(t, Options{})
	for _, target := range []string{backend.URL, "http://169.254.169.254/latest/meta-data"} {
		resp, err := c.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", target, resp.StatusCode)
		}
	}
	// a private location may reach the backend, but never the metadata address
	c = proxyClient(t, Options{AllowPrivate: true})
	resp, err := c.Get(backend.URL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("private proxy: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	resp, err = c.Get("http://169.254.169.254/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("metadata via private proxy: %d", resp.StatusCode)
	}
}

// The check runs on the address the kernel is about to connect to, so a name that resolves to a
// blocked address (DNS rebinding) is refused even though the name looked public.
func TestProxyRefusesRebindingName(t *testing.T) {
	c := proxyClient(t, Options{Block: func(ip netip.Addr) bool { return ip.IsLoopback() }})
	resp, err := c.Get("http://localhost:1/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
}
