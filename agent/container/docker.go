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
type Docker struct{ HTTP *http.Client }

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
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
	}
	if err := d.get(ctx, "/containers/json", &raw); err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(raw))
	for _, r := range raw {
		name := r.ID[:min(12, len(r.ID))]
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		out = append(out, Info{ID: r.ID, Name: name, Image: r.Image})
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
	q := url.Values{"since": {fmt.Sprint(since.Unix())}, "filters": {`{"type":["container"]}`}}
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
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Action == "" {
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
			p.emit(out, c, st)
			return nil
		})
	}
	_ = g.Wait()
	return list, nil
}

func (p *Poller) emit(out sink.Sink, c Info, st Stats) {
	attrs := withRes(map[string]string{"container.id": c.ID, "container.name": c.Name, "container.image.name": c.Image})
	p.mu.Lock()
	before, ok := p.prev[c.ID]
	p.prev[c.ID] = st
	p.mu.Unlock()
	if ok && st.At.After(before.At) && st.CPUTotalNS >= before.CPUTotalNS {
		cores := float64(st.CPUTotalNS-before.CPUTotalNS) / float64(st.At.Sub(before.At).Nanoseconds())
		out.Gauge("container.cpu.usage", "{cpu}", cores, attrs, st.At)
	}
	out.Gauge("container.memory.usage", "By", float64(st.MemUsage), attrs, st.At)
}

// Prune forgets containers that are no longer reported.
func (p *Poller) Prune(seen map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.prev {
		if !seen[id] {
			delete(p.prev, id)
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
