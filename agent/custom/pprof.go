package custom

// Pull-mode profiling (CFT-A15, Alloy pyroscope.scrape parity): GET <target>/debug/pprof/<type>
// from Go processes (net/http/pprof) found by static targets or any sd_configs of the
// prometheus module, and post the pprof (already gzip'd by Go) to /v1/profiles. Targets and SD
// are local-file only; remote config can only toggle the module.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// PprofConfig is the `pprof_scrape` module config.
type PprofConfig struct {
	Targets    []TargetSpec `json:"targets"`     // url = http(s)://host:port; labels.service names the service
	SDConfigs  []SDConfig   `json:"sd_configs"`  // any discovery the prometheus module has
	Profiles   []string     `json:"profiles"`    // default cpu, heap, goroutine
	Interval   string       `json:"interval"`    // default 60s
	CPUSeconds int          `json:"cpu_seconds"` // default 10, at most interval - 5s
}

var pprofPaths = map[string]string{"cpu": "profile", "heap": "heap", "goroutine": "goroutine", "mutex": "mutex", "block": "block", "allocs": "allocs"}

// PostProfile uploads one gzip'd pprof for service.
type PostProfile func(ctx context.Context, service, sampleType string, gz []byte) error

// PprofScrape runs until ctx ends.
func PprofScrape(ctx context.Context, raw json.RawMessage, post PostProfile) error {
	var c PprofConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("pprof_scrape: %w", err)
	}
	every := time.Minute
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		if err != nil || d < 15*time.Second {
			return errors.New("pprof_scrape: interval must be at least 15s")
		}
		every = d
	}
	secs := c.CPUSeconds
	if secs <= 0 {
		secs = 10
	}
	secs = min(secs, int(every.Seconds())-5)
	if len(c.Profiles) == 0 {
		c.Profiles = []string{"cpu", "heap", "goroutine"}
	}
	for _, p := range c.Profiles {
		if pprofPaths[p] == "" {
			return fmt.Errorf("pprof_scrape: unknown profile %q", p)
		}
	}
	hc := netguard.Guarded("agent", time.Duration(secs+20)*time.Second)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		targets := append([]TargetSpec(nil), c.Targets...)
		for _, sd := range c.SDConfigs {
			ts, err := sd.discover(ctx, hc)
			if err != nil {
				slog.Warn("pprof_scrape: discovery failed", "type", sd.Type, "error", err)
				continue
			}
			targets = append(targets, ts...)
		}
		for _, tg := range targets {
			go scrapePprof(ctx, hc, tg, c.Profiles, secs, post)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// pprofURL is the profile URL of a target; an SD target's __address__ becomes http://addr.
func pprofURL(tg TargetSpec, profile string, secs int) (string, error) {
	base := tg.URL
	if a := tg.Labels["__address__"]; base == "" && a != "" {
		base = cmpOr(tg.Labels["__scheme__"], "http") + "://" + a
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("target needs an http(s) url or __address__")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/debug/pprof/" + pprofPaths[profile]
	q := url.Values{}
	if profile == "cpu" {
		q.Set("seconds", fmt.Sprint(secs))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func scrapePprof(ctx context.Context, hc *http.Client, tg TargetSpec, profiles []string, secs int, post PostProfile) {
	svc := cmpOr(tg.Labels["service"], cmpOr(tg.Labels["job"], tg.Labels["__address__"]))
	for _, p := range profiles {
		u, err := pprofURL(tg, p, secs)
		if err != nil {
			slog.Debug("pprof_scrape: target skipped", "error", err)
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return
		}
		resp, err := hc.Do(req)
		if err != nil {
			slog.Debug("pprof_scrape: target unreachable", "service", svc)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
			slog.Debug("pprof_scrape: not a gzip'd pprof", "service", svc, "profile", p, "status", resp.StatusCode)
			continue
		}
		if err := post(ctx, svc, p, b); err != nil {
			slog.Warn("pprof_scrape: upload failed", "service", svc, "error", err)
		}
	}
}
