package integrations

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// StatusTarget is one status page. Kind picks the format; Service names the instance (default:
// the kind) and becomes the `service` label of every metric of the target, so two nginx
// servers or an nginx and an Elasticsearch on one host stay apart.
type StatusTarget struct {
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Timeout of one fetch (default 10s, at most 30s).
	Timeout string `json:"timeout"`
}

// HTTPStatusConfig is the http_status module's config: up to 16 targets, local file only.
type HTTPStatusConfig struct {
	Base
	Targets []StatusTarget `json:"targets"`
}

const maxStatusTargets = 16

func (c *HTTPStatusConfig) check() error {
	if len(c.Targets) == 0 || len(c.Targets) > maxStatusTargets {
		return fmt.Errorf("http_status: targets must hold 1 to %d entries", maxStatusTargets)
	}
	seen := map[string]bool{}
	for i := range c.Targets {
		t := &c.Targets[i]
		if _, ok := statusParsers[t.Kind]; !ok {
			return fmt.Errorf("http_status: kind %q is not nginx, apache, haproxy or elasticsearch", t.Kind)
		}
		if !strings.HasPrefix(t.URL, "http://") && !strings.HasPrefix(t.URL, "https://") {
			return fmt.Errorf("http_status: target %d needs an http(s) url", i)
		}
		if t.Service == "" {
			t.Service = t.Kind
		}
		if seen[t.Kind+"/"+t.Service] {
			return fmt.Errorf("http_status: two %s targets share the service %q; set distinct service names", t.Kind, t.Service)
		}
		seen[t.Kind+"/"+t.Service] = true
		if t.Timeout != "" {
			if d, err := time.ParseDuration(t.Timeout); err != nil || d <= 0 || d > 30*time.Second {
				return fmt.Errorf("http_status: timeout %q must be a duration up to 30s", t.Timeout)
			}
		}
	}
	return nil
}

// tagged adds the target's service label to everything a parser writes.
type tagged struct {
	sink.Sink
	service string
}

func (t tagged) Gauge(name, unit string, v float64, a map[string]string, at time.Time) {
	t.Sink.Gauge(name, unit, v, sink.With(a, "service", t.service), at)
}

func (t tagged) Sum(name, unit string, v float64, a map[string]string, at time.Time) {
	t.Sink.Sum(name, unit, v, sink.With(a, "service", t.service), at)
}

// HTTPStatus reads the status page of nginx (stub_status), Apache (mod_status ?auto), HAProxy
// (stats ;csv) or Elasticsearch (_cluster/health) for every target, concurrently, each under its
// own timeout. Each target reports `wt.integration.up{integration=<kind>,service=<service>}`.
func HTTPStatus(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPStatusConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "http_status", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		var wg sync.WaitGroup
		for _, t := range c.Targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d := 10 * time.Second
				if p, err := time.ParseDuration(t.Timeout); err == nil {
					d = p
				}
				tctx, cancel := context.WithTimeout(ctx, d)
				defer cancel()
				up := 1.0
				b, err := getBody(tctx, HTTPConfig{Username: t.Username, Password: t.Password}, t.URL)
				if err == nil {
					err = statusParsers[t.Kind](tagged{out, t.Service}, b, now)
				}
				if err != nil {
					up = 0
					slog.Warn("status page failed", "integration", t.Kind, "service", t.Service, "error", sink.Truncate(err.Error(), 300))
				}
				out.Gauge("wt.integration.up", "1", up, map[string]string{"integration": t.Kind, "service": t.Service}, now)
			}()
		}
		wg.Wait()
		return nil
	})
}

var statusParsers = map[string]func(sink.Sink, []byte, time.Time) error{
	"nginx": EmitNginx, "apache": EmitApache, "haproxy": EmitHAProxy, "elasticsearch": EmitElasticsearch,
}

// EmitNginx parses stub_status.
func EmitNginx(out sink.Sink, b []byte, now time.Time) error {
	// Active connections: 291 \n server accepts handled requests \n 16630948 16630948 31070465 \n
	// Reading: 6 Writing: 179 Waiting: 106
	var active, accepts, handled, requests, reading, writing, waiting float64
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 4 {
		return fmt.Errorf("nginx: not stub_status output")
	}
	if _, err := fmt.Sscanf(lines[0], "Active connections: %g", &active); err != nil {
		return fmt.Errorf("nginx: not stub_status output")
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(lines[2]), "%g %g %g", &accepts, &handled, &requests); err != nil {
		return fmt.Errorf("nginx: bad counters")
	}
	_, _ = fmt.Sscanf(lines[3], "Reading: %g Writing: %g Waiting: %g", &reading, &writing, &waiting)
	out.Gauge("nginx.connections.active", "{connections}", active, nil, now)
	out.Gauge("nginx.connections.reading", "{connections}", reading, nil, now)
	out.Gauge("nginx.connections.writing", "{connections}", writing, nil, now)
	out.Gauge("nginx.connections.waiting", "{connections}", waiting, nil, now)
	out.Sum("nginx.connections.accepted", "{connections}", accepts, nil, now)
	out.Sum("nginx.connections.handled", "{connections}", handled, nil, now)
	out.Sum("nginx.requests", "{requests}", requests, nil, now)
	return nil
}

// EmitApache parses mod_status `?auto`.
func EmitApache(out sink.Sink, b []byte, now time.Time) error {
	kv := map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ": "); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				kv[k] = f
			}
		}
	}
	if _, ok := kv["BusyWorkers"]; !ok {
		return fmt.Errorf("apache: not mod_status ?auto output")
	}
	out.Gauge("apache.workers.busy", "{workers}", kv["BusyWorkers"], nil, now)
	out.Gauge("apache.workers.idle", "{workers}", kv["IdleWorkers"], nil, now)
	out.Gauge("apache.uptime", "s", kv["ServerUptimeSeconds"], nil, now)
	out.Sum("apache.requests", "{requests}", kv["Total Accesses"], nil, now)
	out.Sum("apache.traffic", "kBy", kv["Total kBytes"], nil, now)
	return nil
}

// EmitHAProxy parses the CSV stats page: per proxy and server status, sessions, errors.
func EmitHAProxy(out sink.Sink, b []byte, now time.Time) error {
	b = bytes.TrimPrefix(b, []byte("# "))
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	head, err := r.Read()
	if err != nil {
		return fmt.Errorf("haproxy: not stats csv")
	}
	col := map[string]int{}
	for i, h := range head {
		col[h] = i
	}
	if _, ok := col["svname"]; !ok {
		return fmt.Errorf("haproxy: not stats csv")
	}
	get := func(rec []string, k string) string {
		if i, ok := col[k]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	n := 0
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n++; n > 2000 {
			break
		}
		a := map[string]string{"proxy": get(rec, "pxname"), "server": get(rec, "svname")}
		status := get(rec, "status")
		up := 0.0
		if strings.HasPrefix(status, "UP") || status == "OPEN" {
			up = 1
		}
		out.Gauge("haproxy.up", "1", up, a, now)
		for k, name := range map[string]string{"scur": "haproxy.sessions.current", "qcur": "haproxy.queue.current"} {
			if f, err := strconv.ParseFloat(get(rec, k), 64); err == nil {
				out.Gauge(name, "1", f, a, now)
			}
		}
		for k, name := range map[string]string{"stot": "haproxy.sessions.total", "hrsp_5xx": "haproxy.responses.5xx",
			"econ": "haproxy.connection_errors"} {
			if f, err := strconv.ParseFloat(get(rec, k), 64); err == nil {
				out.Sum(name, "1", f, a, now)
			}
		}
	}
	return nil
}

// EmitElasticsearch parses _cluster/health. Status is 0 green, 1 yellow, 2 red.
func EmitElasticsearch(out sink.Sink, b []byte, now time.Time) error {
	var h struct {
		Status       string  `json:"status"`
		Nodes        float64 `json:"number_of_nodes"`
		Unassigned   float64 `json:"unassigned_shards"`
		Initializing float64 `json:"initializing_shards"`
		Relocating   float64 `json:"relocating_shards"`
		ActiveShards float64 `json:"active_shards"`
		PendingTasks float64 `json:"number_of_pending_tasks"`
	}
	if err := json.Unmarshal(b, &h); err != nil || h.Status == "" {
		return fmt.Errorf("elasticsearch: not _cluster/health output")
	}
	status := map[string]float64{"green": 0, "yellow": 1, "red": 2}[h.Status]
	out.Gauge("elasticsearch.cluster.status", "1", status, nil, now)
	out.Gauge("elasticsearch.cluster.nodes", "{nodes}", h.Nodes, nil, now)
	out.Gauge("elasticsearch.shards.unassigned", "{shards}", h.Unassigned, nil, now)
	out.Gauge("elasticsearch.shards.initializing", "{shards}", h.Initializing, nil, now)
	out.Gauge("elasticsearch.shards.relocating", "{shards}", h.Relocating, nil, now)
	out.Gauge("elasticsearch.shards.active", "{shards}", h.ActiveShards, nil, now)
	out.Gauge("elasticsearch.cluster.pending_tasks", "{tasks}", h.PendingTasks, nil, now)
	return nil
}
