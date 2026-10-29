package virt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// common is the part of every virt module config that remote config may change.
type common struct {
	Enabled  *bool  `json:"enabled"`
	Interval string `json:"interval"`
}

// runTargets decodes raw into cfg, then polls every target in parallel, each under its own
// timeout, until ctx ends. A module without targets or switched off just waits.
func runTargets[T any](ctx context.Context, kind string, raw json.RawMessage, cfg any, c *common, targets func() []T,
	name func(T) string, validate func(T) error, poll func(context.Context, T, sink.Sink, time.Time) error,
	out sink.Sink, def time.Duration,
) error {
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, cfg); err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
	}
	ts := targets()
	if c.Enabled != nil && !*c.Enabled || len(ts) == 0 {
		<-ctx.Done()
		return nil
	}
	for _, t := range ts {
		if err := validate(t); err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
	}
	out = sink.Hoist(out)
	host.Every(ctx, host.Duration(c.Interval, def, 10*time.Second), func(ctx context.Context) {
		var wg sync.WaitGroup
		for _, t := range ts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
				defer cancel()
				host.Warn(kind+" "+name(t), poll(cctx, t, out, time.Now()))
			}()
		}
		wg.Wait()
	})
	return nil
}

// checkURL refuses credentials over plain http to anything but a loopback address.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("bad url")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("url must be https (http only for loopback)")
		}
	}
	return nil
}

func secretOf(plain, env string) string {
	if plain != "" {
		return plain
	}
	return os.Getenv(env)
}

func newClient(insecure bool) *http.Client {
	hc := netguard.NewClientWith(netguard.FromEnv("agent"), netguard.Options{}, func(tr *http.Transport) {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in for self-signed management endpoints
		tr.ResponseHeaderTimeout = 10 * time.Second
		tr.DisableKeepAlives = true
	})
	hc.Timeout = 15 * time.Second
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return hc
}

// getJSON runs req and decodes a 200 JSON body (at most 8 MiB) into dst. Errors never carry
// the request URL or headers.
func getJSON(hc *http.Client, req *http.Request, dst any, secrets ...string) error {
	resp, err := hc.Do(req)
	if err != nil {
		return host.Redact(err, secrets...)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxPVEBody)).Decode(dst)
}

func errName(kind string) error {
	return errors.New(kind + ": every target needs a name and a username (the name is part of the VM identity)")
}

func upGauge(ok bool) float64 {
	if ok {
		return 1
	}
	return 0
}
