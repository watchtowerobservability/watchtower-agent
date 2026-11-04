// Package container collects container metrics and events from the Docker Engine API (unix
// socket or Windows named pipe) and, on Linux, from cgroup v2 files for containerd and podman.
package container

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxContainers = 500
	statsParallel = 8
)

// DefaultHost is the engine endpoint when the local config names none.
func DefaultHost() string {
	if runtime.GOOS == "windows" {
		return "npipe:////./pipe/docker_engine"
	}
	return "unix:///var/run/docker.sock"
}

// Docker is a minimal Engine API client. The endpoint comes only from the agent's local file.
// Labels, when set, are sent as a server-side filter on list and events, so the engine never
// returns containers without every one of them (and List re-checks them).
type Docker struct {
	HTTP   *http.Client
	Labels map[string]string
}

// LabelFilter is the Engine API `label` filter for labels: sorted "k=v" values.
func LabelFilter(labels map[string]string) []string {
	out := make([]string, 0, len(labels))
	for k, v := range labels {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// HasLabels reports whether have carries every pair of want.
func HasLabels(have, want map[string]string) bool {
	for k, v := range want {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// filters is the url-encoded `filters` query value: kinds plus the label filter.
func (d *Docker) filters(kinds map[string][]string) string {
	f := map[string][]string{}
	for k, v := range kinds {
		f[k] = v
	}
	if len(d.Labels) > 0 {
		f["label"] = LabelFilter(d.Labels)
	}
	b, _ := json.Marshal(f)
	return string(b)
}

// NewDocker accepts unix:///path and npipe:////./pipe/name endpoints.
func NewDocker(endpoint string) (*Docker, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	var dial func(context.Context, string, string) (net.Conn, error)
	switch u.Scheme {
	case "unix":
		path := u.Path
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
		}
	case "npipe":
		pipe := strings.ReplaceAll(strings.TrimPrefix(endpoint, "npipe://"), "/", `\`)
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) { return dialPipe(ctx, pipe) }
	default:
		return nil, fmt.Errorf("docker endpoint %q: want unix:// or npipe://", endpoint)
	}
	return &Docker{HTTP: &http.Client{Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true}}}, nil
}

// Info is one listed container.
type Info struct {
	ID    string
	Name  string
	Image string
	// State is docker's state word (running, paused, restarting, exited, ...).
	State string
	// Labels are the container labels (watchtower.dev/* drive autodiscovery, see labels.go).
	Labels map[string]string
	// IP is the lowest network address; Ports the distinct private ports, ascending.
	IP    string
	Ports []int
}

func (d *Docker) get(ctx context.Context, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// List returns the running containers (at most maxContainers).
func (d *Docker) List(ctx context.Context) ([]Info, error) {
	var raw []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
		Ports  []struct {
			PrivatePort int `json:"PrivatePort"`
		} `json:"Ports"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	path := "/containers/json"
	if len(d.Labels) > 0 {
		path += "?" + url.Values{"filters": {d.filters(nil)}}.Encode()
	}
	if err := d.get(ctx, path, &raw); err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(raw))
	for _, r := range raw {
		if !HasLabels(r.Labels, d.Labels) {
			continue // the engine filtered already; this guards an engine that ignored the filter
		}
		name := r.ID[:min(12, len(r.ID))]
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		in := Info{ID: r.ID, Name: name, Image: r.Image, State: r.State, Labels: r.Labels}
		for _, n := range r.NetworkSettings.Networks {
			if n.IPAddress != "" && (in.IP == "" || n.IPAddress < in.IP) {
				in.IP = n.IPAddress // lowest address, so a multi-network container resolves stably
			}
		}
		for _, p := range r.Ports {
			if p.PrivatePort > 0 && !slices.Contains(in.Ports, p.PrivatePort) {
				in.Ports = append(in.Ports, p.PrivatePort)
			}
		}
		slices.Sort(in.Ports)
		out = append(out, in)
	}
	if len(out) > maxContainers {
		out = out[:maxContainers]
	}
	return out, nil
}

// Stats is the part of /containers/{id}/stats that the agent uses.
type Stats struct {
	CPUTotalNS uint64 // cumulative CPU time
	MemUsage   uint64 // working set: usage minus reclaimable page cache
	At         time.Time
}

// Stats takes one sample (no streaming, no server-side wait).
func (d *Docker) Stats(ctx context.Context, id string) (Stats, error) {
	var raw struct {
		CPU struct {
			Usage struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
		} `json:"cpu_stats"`
		Mem struct {
			Usage uint64            `json:"usage"`
			Stats map[string]uint64 `json:"stats"`
		} `json:"memory_stats"`
	}
	if err := d.get(ctx, "/containers/"+url.PathEscape(id)+"/stats?stream=false&one-shot=true", &raw); err != nil {
		return Stats{}, err
	}
	mem := raw.Mem.Usage
	reclaim := raw.Mem.Stats["inactive_file"] // cgroup v2
	if reclaim == 0 {
		reclaim = raw.Mem.Stats["total_inactive_file"] // v1
	}
	if reclaim < mem {
		mem -= reclaim
	}
	return Stats{CPUTotalNS: raw.CPU.Usage.Total, MemUsage: mem, At: time.Now()}, nil
}

// Events streams container events as log records until ctx ends or the stream breaks.
func (d *Docker) Events(ctx context.Context, since time.Time, out sink.Sink) error {
	q := url.Values{"since": {fmt.Sprint(since.Unix())}, "filters": {d.filters(map[string][]string{"type": {"container"}})}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/events?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e struct {
			Action string `json:"Action"`
			Actor  struct {
				ID    string            `json:"ID"`
				Attrs map[string]string `json:"Attributes"`
			} `json:"Actor"`
			Time int64 `json:"time"`
		}
		// exec_* is every healthcheck run (~3 rows per container per interval); health_status already says the outcome.
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Action == "" || strings.HasPrefix(e.Action, "exec_") {
			continue
		}
		sev := "INFO"
		if e.Action == "die" || e.Action == "oom" || strings.HasPrefix(e.Action, "health_status: unhealthy") {
			sev = "WARN"
		}
		a := withRes(map[string]string{
			"container.id": e.Actor.ID, "container.name": e.Actor.Attrs["name"],
			"container.image.name": e.Actor.Attrs["image"],
		})
		a["container.event"] = e.Action
		out.Log(sev, "container "+e.Action, a, time.Unix(e.Time, 0))
	}
	return sc.Err()
}

// Poller turns successive samples into cores-used gauges.
type Poller struct {
	mu   sync.Mutex
	prev map[string]Stats
	// Services maps compose service names to identities (Config.Services).
	Services map[string]ServiceMap
	ids      map[string]Identity // per container id, resolved once (env does not change)
}

// Env returns the container's environment (NAME=value) from the engine.
func (d *Docker) Env(ctx context.Context, id string) ([]string, error) {
	var raw struct {
		Config struct {
			Env []string `json:"Env"`
		} `json:"Config"`
	}
	if err := d.get(ctx, "/containers/"+id+"/json", &raw); err != nil {
		return nil, err
	}
	return raw.Config.Env, nil
}

// identity resolves (and caches) the container's service identity. A failed inspect is not cached.
func (p *Poller) identity(ctx context.Context, d *Docker, c Info) Identity {
	p.mu.Lock()
	id, ok := p.ids[c.ID]
	p.mu.Unlock()
	if ok {
		return id
	}
	env, err := d.Env(ctx, c.ID)
	id = ResolveIdentity(env, c.Labels, p.Services, c.Name)
	if err == nil {
		p.mu.Lock()
		if p.ids == nil {
			p.ids = map[string]Identity{}
		}
		p.ids[c.ID] = id
		p.mu.Unlock()
	}
	return id
}

// Collect samples every listed container and writes container.cpu.usage (cores in use, from the
// change since the last pass; none on the first) and container.memory.usage (bytes).
func (p *Poller) Collect(ctx context.Context, d *Docker, out sink.Sink) ([]Info, error) {
	list, err := d.List(ctx)
	if err != nil {
		return nil, err
	}
	if p.prev == nil {
		p.prev = map[string]Stats{}
	}
	var g errgroup.Group
	g.SetLimit(statsParallel)
	for _, c := range list {
		g.Go(func() error {
			st, err := d.Stats(ctx, c.ID)
			if err != nil {
				return nil // a container that just exited is not an error
			}
			p.emit(out, c, st, p.identity(ctx, d, c))
			return nil
		})
	}
	_ = g.Wait()
	return list, nil
}

func (p *Poller) emit(out sink.Sink, c Info, st Stats, id Identity) {
	attrs := withRes(map[string]string{"container.id": c.ID, "container.name": c.Name, "container.image.name": c.Image})
	for k, v := range sink.Res(id.Resource()) {
		attrs[k] = v
	}
	p.mu.Lock()
	before, ok := p.prev[c.ID]
	p.prev[c.ID] = st
	p.mu.Unlock()
	if ok && st.At.After(before.At) && st.CPUTotalNS >= before.CPUTotalNS {
		cores := float64(st.CPUTotalNS-before.CPUTotalNS) / float64(st.At.Sub(before.At).Nanoseconds())
		gaugeProm(out, "container.cpu.usage", "{cpu}", cores, attrs, st.At)
	}
	gaugeProm(out, "container.memory.usage", "By", float64(st.MemUsage), attrs, st.At)
}

// PromName converts an OTLP metric name to a PromQL-safe one: every character outside
// [a-zA-Z0-9_:] becomes an underscore (container.cpu.usage -> container_cpu_usage).
func PromName(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == ':' {
			return r
		}
		return '_'
	}, name)
}

// gaugeProm emits the canonical OTLP (dotted) name and, on the PromQL exposition path, its
// underscored alias (see otlp-metric-names.md).
func gaugeProm(out sink.Sink, name, unit string, v float64, attrs map[string]string, at time.Time) {
	out.Gauge(name, unit, v, attrs, at)
	if pn := PromName(name); pn != name {
		out.Gauge(pn, unit, v, attrs, at)
	}
}

// Prune forgets containers that are no longer reported.
func (p *Poller) Prune(seen map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.prev {
		if !seen[id] {
			delete(p.prev, id)
			delete(p.ids, id)
		}
	}
}

// withRes keeps the container identity as ordinary attributes and also puts it on the resource
// (sink.ResourcePrefix keys, which only a Hoist-wrapped sink turns into resource attributes), so
// the worker makes a container entity of it. The docker module is trusted to name the resource
// because the Engine API, not scraped input, supplies these three values.
func withRes(a map[string]string) map[string]string {
	for k, v := range sink.Res(a) {
		a[k] = v
	}
	return a
}
