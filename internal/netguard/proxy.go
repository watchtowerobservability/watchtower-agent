package netguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proxy is a local forward proxy (HTTP and CONNECT) whose upstream dialer applies the address
// policy at connect time, so a child process such as k6 that honours HTTP_PROXY/HTTPS_PROXY
// reaches no private range, metadata address or rebound name on a public location.
// shortcut: processes that bypass proxies for loopback (Go's localhost rule) are not covered;
// upgrade to a network namespace if scripts must be fully contained.
type Proxy struct {
	ln   net.Listener
	srv  *http.Server
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewProxy starts the proxy on 127.0.0.1 with an ephemeral port.
func NewProxy(o Options) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, dial: New(o).DialContext}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// URL is the value for HTTP_PROXY and HTTPS_PROXY.
func (p *Proxy) URL() string { return "http://" + p.ln.Addr().String() }

// Close stops the proxy.
func (p *Proxy) Close() error { return p.srv.Close() }

func (p *Proxy) fail(w http.ResponseWriter, err error) {
	code := http.StatusBadGateway
	if errors.Is(err, ErrBlocked) || strings.Contains(err.Error(), ErrBlocked.Error()) {
		code = http.StatusForbidden
	}
	http.Error(w, "proxy: "+ErrBlocked.Error(), code)
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "proxy: absolute URL required", http.StatusBadRequest)
		return
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	tr := &http.Transport{DialContext: p.dial, Proxy: nil, ResponseHeaderTimeout: time.Minute}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(r)
	if err != nil {
		p.fail(w, err)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	up, err := p.dial(r.Context(), "tcp", r.Host)
	if err != nil {
		p.fail(w, err)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "proxy: cannot hijack", http.StatusInternalServerError)
		return
	}
	c, _, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}
	go pipe(up, c)
	go pipe(c, up)
	wg.Wait()
	_ = c.Close()
	_ = up.Close()
}
