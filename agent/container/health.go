package container

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// HealthTarget is one probe the agent runs itself over the compose network (socket-free health).
type HealthTarget struct {
	Name     string // container or service the series is reported for
	URL      string // http://host:port/path, https://..., or tcp://host:port
	Interval time.Duration
	Timeout  time.Duration
	// Status is the expected http status: "200", or a class such as "2xx"; empty means below 400.
	Status string
}

// HealthConfig is one static `cgroups.health` entry (local file only).
type HealthConfig struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Interval string `json:"interval"` // default 30s, at least 5s
	Timeout  string `json:"timeout"`  // default 5s, at most 30s
	Status   string `json:"status"`   // expected http status ("200", "2xx"); default any below 400
}

// ParseHealth builds the target of a `wt.health` label value. The host may be empty (the
// container name) or the container's own name or compose service: a label comes from whoever can
// start containers, so it can never aim the agent at another host. Static config (trusted)
// passes any host through ParseHealthTarget.
func ParseHealth(name, service string, labels map[string]string) (HealthTarget, bool, error) {
	v := labels["wt.health"]
	if v == "" {
		return HealthTarget{}, false, nil
	}
	t, err := ParseHealthTarget(name, v, labels["wt.health.interval"], labels["wt.health.timeout"], name, labels["wt.health.status"])
	if err != nil {
		return t, true, err
	}
	u, _ := url.Parse(t.URL)
	if h := u.Hostname(); h != name && (service == "" || h != service) {
		return t, true, fmt.Errorf("wt.health host %q must be empty or the container's own name/service", h)
	}
	return t, true, nil
}

// ParseHealthTarget parses a target URL; an empty host becomes defHost.
func ParseHealthTarget(name, target, interval, timeout, defHost, status string) (HealthTarget, error) {
	u, err := url.Parse(target)
	if err != nil || !slices.Contains([]string{"http", "https", "tcp", "postgres", "redis"}, u.Scheme) || u.User != nil {
		return HealthTarget{}, fmt.Errorf("health target %q: want http://, https://, tcp://, postgres:// or redis:// with host:port", target)
	}
	port := u.Port()
	if u.Hostname() == "" {
		if defHost == "" {
			return HealthTarget{}, fmt.Errorf("health target %q has no host", target)
		}
		u.Host = defHost
		if port != "" {
			u.Host += ":" + port
		}
	}
	if u.Port() == "" {
		def := map[string]string{"http": "80", "https": "443", "postgres": "5432", "redis": "6379"}[u.Scheme]
		if def == "" {
			return HealthTarget{}, fmt.Errorf("health target %q: tcp needs a port", target)
		}
		u.Host += ":" + def
	}
	return HealthTarget{Name: name, URL: u.String(), Interval: host.Duration(interval, 30*time.Second, 5*time.Second),
		Timeout: min(host.Duration(timeout, 5*time.Second, time.Second), 30*time.Second), Status: status}, nil
}

// probe runs one check: http(s) answers below 400 (redirects are not followed), tcp connects.
func (t HealthTarget) probe(ctx context.Context) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	start := time.Now()
	u, _ := url.Parse(t.URL)
	if u.Scheme != "http" && u.Scheme != "https" {
		return probeProto(ctx, u.Scheme, u.Host), time.Since(start)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return false, 0
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return false, time.Since(start)
	}
	_ = resp.Body.Close()
	return statusOK(t.Status, resp.StatusCode), time.Since(start)
}

// healthState schedules probes and remembers the last verdict per target.
type healthState struct {
	next map[string]time.Time
	last map[string]bool
}

// Health probes the targets that are due and emits container.health (1 healthy, 0 not),
// container.health.latency (ms) with source=probe, and a container.event record on every change
// (the names Docker's health_status events use). It runs inside the module tick, so an interval
// shorter than the module interval is rounded up to it.
func (p *Poller) Health(ctx context.Context, out sink.Sink, targets []HealthTarget, attrs func(HealthTarget) map[string]string) {
	if p.health == nil {
		p.health = &healthState{next: map[string]time.Time{}, last: map[string]bool{}}
	}
	now := time.Now()
	live := map[string]bool{}
	for _, t := range targets {
		live[t.URL] = true
		if now.Before(p.health.next[t.URL]) {
			continue
		}
		p.health.next[t.URL] = now.Add(t.Interval)
		ok, lat := t.probe(ctx)
		a := sink.With(attrs(t), "source", "probe", "health.target", t.URL)
		v := 0.0
		if ok {
			v = 1
		}
		gaugeProm(out, "container.health", "1", v, a, now)
		gaugeProm(out, "container.health.latency", "ms", float64(lat.Microseconds())/1000, a, now)
		if was, seen := p.health.last[t.URL]; !seen || was != ok {
			p.health.last[t.URL] = ok
			state, sev := "healthy", "INFO"
			if !ok {
				state, sev = "unhealthy", "WARN"
			}
			if seen || !ok {
				out.Log(sev, "container health_status: "+state, sink.With(a, "container.event", "health_status: "+state), now)
			}
		}
	}
	for k := range p.health.next {
		if !live[k] {
			delete(p.health.next, k)
			delete(p.health.last, k)
		}
	}
}

// ProbeLearned probes the static targets and the wt.health label of every reported container.
func (p *Poller) ProbeLearned(ctx context.Context, out sink.Sink, reported map[string]bool) {
	live := map[string]Learned{}
	if !p.NoLearned {
		for id := range reported {
			if l, ok := Lookup(id); ok {
				live[id] = l
			}
		}
	}
	ts, errs := healthTargets(p.StaticHealth, live)
	for _, e := range errs {
		slog.Warn("container: ignoring health label", "error", e)
	}
	p.Health(ctx, out, ts, func(t HealthTarget) map[string]string {
		return withRes(map[string]string{"container.name": t.Name})
	})
}

// healthTargets are the static targets plus those of live containers whose learned labels carry wt.health.
func healthTargets(static []HealthTarget, live map[string]Learned) ([]HealthTarget, []error) {
	out := append([]HealthTarget(nil), static...)
	var errs []error
	for _, l := range live {
		t, has, err := ParseHealth(l.Name, l.Service, l.Labels)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", l.Name, err))
		case has:
			out = append(out, t)
		}
	}
	return out, errs
}

// StaticHealth parses `cgroups.health`.
func StaticHealth(cfg []HealthConfig) ([]HealthTarget, error) {
	var out []HealthTarget
	for _, h := range cfg {
		t, err := ParseHealthTarget(h.Name, h.Target, h.Interval, h.Timeout, "", h.Status)
		if err != nil {
			return nil, err
		}
		if t.Name == "" {
			t.Name = strings.TrimPrefix(t.URL, "tcp://")
		}
		out = append(out, t)
	}
	return out, nil
}

// statusOK: want is "" (any below 400), an exact code ("204") or a class ("2xx").
func statusOK(want string, code int) bool {
	switch {
	case want == "":
		return code < 400
	case len(want) == 3 && strings.HasSuffix(want, "xx"):
		return strconv.Itoa(code)[:1] == want[:1]
	}
	return strconv.Itoa(code) == want
}

// probeProto connects and, for postgres and redis, speaks just enough of the protocol to know the
// server answers, without credentials: postgres gets an SSLRequest (any S/N reply is "up"), redis
// a PING (+PONG, or -NOAUTH/-NOPERM when it wants a password, is "up"). Bare tcp only connects.
func probeProto(ctx context.Context, scheme, addr string) bool {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	buf := make([]byte, 16)
	switch scheme {
	case "postgres":
		if _, err := c.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
			return false
		}
		n, _ := c.Read(buf)
		return n == 1 && (buf[0] == 'S' || buf[0] == 'N')
	case "redis":
		if _, err := c.Write([]byte("PING\r\n")); err != nil {
			return false
		}
		n, _ := c.Read(buf)
		return redisUp(string(buf[:n]))
	}
	return true
}

func redisUp(reply string) bool {
	return strings.HasPrefix(reply, "+PONG") || strings.HasPrefix(reply, "-NOAUTH") || strings.HasPrefix(reply, "-NOPERM")
}
