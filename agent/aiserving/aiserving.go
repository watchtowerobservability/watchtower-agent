// Package aiserving scrapes Prometheus text endpoints of model servers (vLLM, Triton, TGI) and
// the NVIDIA DCGM exporter and re-emits them under OTel-style names.
//
// shortcut: histograms are reduced to the mean over each scrape interval (sum and count deltas),
// not re-emitted as buckets; upgrade to a histogram data point if p95 from the agent is needed.
package aiserving

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

type kind int

const (
	gauge kind = iota
	histMean
	ratioMean
)

// mapping turns one Prometheus family into one OTel-style metric. Scale 0 means 1.
type mapping struct {
	Prom, Den, Name, Unit string
	Kind                  kind
	Scale                 float64
}

var kinds = map[string][]mapping{"vllm": vllm, "triton": triton, "tgi": tgi, "dcgm": dcgm}

// series is one parsed sample line.
type series struct {
	name   string
	labels map[string]string
	value  float64
}

// parse reads the Prometheus text exposition format. Comments, timestamps and malformed lines
// are skipped; NaN and infinite values are dropped.
func parse(r io.Reader) []series {
	var out []series
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name, rest := line, ""
		labels := map[string]string{}
		if i := strings.IndexByte(line, '{'); i >= 0 {
			name = line[:i]
			var ok bool
			if labels, rest, ok = parseLabels(line[i+1:]); !ok {
				continue
			}
		} else if i := strings.IndexAny(line, " \t"); i >= 0 {
			name, rest = line[:i], line[i:]
		}
		f := strings.Fields(rest) // value [timestamp]
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, series{name: name, labels: labels, value: v})
	}
	return out
}

// parseLabels reads `k="v",k2="v2"} rest` and returns the labels and what follows the brace.
func parseLabels(s string) (map[string]string, string, bool) {
	m := map[string]string{}
	for {
		s = strings.TrimLeft(s, ", ")
		if strings.HasPrefix(s, "}") {
			return m, s[1:], true
		}
		eq := strings.Index(s, `="`)
		if eq < 0 {
			return nil, "", false
		}
		k := strings.TrimSpace(s[:eq])
		s = s[eq+2:]
		var v strings.Builder
		closed := false
		for i := 0; i < len(s); i++ {
			switch {
			case s[i] == '\\' && i+1 < len(s):
				i++
				if s[i] == 'n' {
					v.WriteByte('\n')
				} else {
					v.WriteByte(s[i])
				}
			case s[i] == '"':
				s, closed = s[i+1:], true
			default:
				v.WriteByte(s[i])
			}
			if closed {
				break
			}
		}
		if !closed {
			return nil, "", false
		}
		m[k] = v.String()
	}
}

// labelKey identifies a series within a family: sorted labels without le and quantile.
func labelKey(l map[string]string) string {
	ks := make([]string, 0, len(l))
	for k := range l {
		if k != "le" && k != "quantile" {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k + "=" + l[k] + ",")
	}
	return b.String()
}

// attrs keeps the few labels worth a dimension; hostnames and the rest would multiply series.
func attrs(server string, l map[string]string) map[string]string {
	a := map[string]string{"ai.server.kind": server}
	for from, to := range map[string]string{
		"model_name": "gen_ai.request.model", "model": "gen_ai.request.model", "modelName": "hw.name",
		"gpu": "gpu.index", "UUID": "hw.id", "gpu_uuid": "hw.id", "version": "model.version",
		"GPU_I_ID": "gpu.mig.instance", "GPU_I_PROFILE": "gpu.mig.profile",
	} {
		if v := l[from]; v != "" {
			a[to] = v
		}
	}
	return a
}

type pair struct{ num, den float64 }

// Scraper keeps the previous sums and counts so each emitted mean covers one interval.
type Scraper struct{ prev map[string]pair }

// Map emits the metrics of body for one server kind.
func (s *Scraper) Map(server, target string, body []byte, out sink.Sink, at time.Time) error {
	ms, ok := kinds[server]
	if !ok {
		return fmt.Errorf("unknown server kind %q", server)
	}
	if s.prev == nil {
		s.prev = map[string]pair{}
	}
	all := parse(bytes.NewReader(body))
	byName := map[string][]series{}
	for _, x := range all {
		byName[x.name] = append(byName[x.name], x)
	}
	for _, m := range ms {
		scale := m.Scale
		if scale == 0 {
			scale = 1
		}
		numName, denName := m.Prom, m.Den
		if m.Kind == histMean {
			numName, denName = m.Prom+"_sum", m.Prom+"_count"
		}
		if m.Kind == gauge {
			for _, x := range byName[numName] {
				out.Gauge(m.Name, m.Unit, x.value*scale, attrs(server, x.labels), at)
			}
			continue
		}
		dens := map[string]float64{}
		for _, d := range byName[denName] {
			dens[labelKey(d.labels)] = d.value
		}
		for _, n := range byName[numName] {
			key := labelKey(n.labels)
			d, ok := dens[key]
			if !ok {
				continue
			}
			id := target + "|" + numName + "|" + key
			p, seen := s.prev[id]
			s.prev[id] = pair{n.value, d}
			dn, dd := n.value, d
			if seen && d >= p.den && n.value >= p.num { // a restart resets counters: use the lifetime mean
				dn, dd = n.value-p.num, d-p.den
			}
			if dd > 0 {
				out.Gauge(m.Name, m.Unit, dn/dd*scale, attrs(server, n.labels), at)
			}
		}
	}
	return nil
}

// Target is one endpoint to scrape.
type Target struct {
	Kind string `json:"kind"` // vllm, triton, tgi or dcgm
	URL  string `json:"url"`
}

// Config is the aiserving module's config. Only Enabled and Interval can be set remotely.
type Config struct {
	Enabled  *bool    `json:"enabled"`
	Interval string   `json:"interval"` // default 15s, at least 5s
	Targets  []Target `json:"targets"`
	// AllowRemote lets targets be non-loopback hosts. Off by default so the agent is never a
	// scraper of arbitrary hosts; set it in the agent's own file only.
	AllowRemote bool `json:"allow_remote"`
}

// Validate checks every target: a known kind, an http(s) URL, and loopback unless AllowRemote.
func (c Config) Validate() error {
	for _, t := range c.Targets {
		if _, ok := kinds[t.Kind]; !ok {
			return fmt.Errorf("aiserving: unknown kind %q", t.Kind)
		}
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return fmt.Errorf("aiserving: target %q is not an http(s) URL", t.URL)
		}
		if !c.AllowRemote && !isLocal(u.Hostname()) {
			return fmt.Errorf("aiserving: target host %q is not local (set allow_remote in the agent file)", u.Hostname())
		}
	}
	return nil
}

func isLocal(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Run scrapes until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 {
		<-ctx.Done()
		return nil
	}
	cl := netguard.GuardedNoRedirect("agent", 10*time.Second)
	var s Scraper
	t := time.NewTicker(host.Duration(c.Interval, 15*time.Second, 5*time.Second))
	defer t.Stop()
	for {
		for _, tg := range c.Targets {
			if b, err := fetch(ctx, cl, tg.URL); err == nil {
				_ = s.Map(tg.Kind, tg.URL, b, out, time.Now())
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func fetch(ctx context.Context, cl *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape %s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}
