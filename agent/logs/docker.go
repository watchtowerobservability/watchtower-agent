package logs

// Docker API log follower (CFT-A07, Alloy loki.source.docker parity): every running container
// on the engine (unix socket or TCP URL) is followed through GET /containers/{id}/logs, new
// containers are picked up every 10 s. The last timestamp per container is kept in the state
// dir, so a restart continues where it stopped (at-least-once: the boundary line may repeat).

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// DockerLogs selects the engine and containers.
type DockerLogs struct {
	Host   string            `json:"host"`   // unix:///var/run/docker.sock (default) or http(s)://
	Labels map[string]string `json:"labels"` // only containers carrying every label (server-side filter)
	// RequireLabels makes empty Labels follow nothing instead of every container (shared hosts).
	RequireLabels bool `json:"require_labels"`
}

type dockerFollower struct {
	c       DockerLogs
	hc      *http.Client
	base    string
	out     sink.Sink
	state   string
	mu      sync.Mutex
	since   map[string]int64 // container id -> unix nanos of the last line
	running map[string]bool
}

func newDockerFollower(c DockerLogs, stateDir string, out sink.Sink) *dockerFollower {
	host := c.Host
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	f := &dockerFollower{c: c, out: out, since: map[string]int64{}, running: map[string]bool{}, base: strings.TrimRight(host, "/")}
	if sock, ok := strings.CutPrefix(host, "unix://"); ok {
		f.base = "http://docker"
		f.hc = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
		}}}
	} else {
		f.hc = &http.Client{}
	}
	if stateDir != "" {
		f.state = filepath.Join(stateDir, "docker-logs.json")
		if b, err := os.ReadFile(f.state); err == nil {
			_ = json.Unmarshal(b, &f.since)
		}
	}
	return f
}

// RunDocker follows container logs until ctx ends.
func RunDocker(ctx context.Context, c DockerLogs, stateDir string, out sink.Sink) error {
	if c.RequireLabels && len(c.Labels) == 0 {
		slog.Warn("docker logs: require_labels is set but labels are empty; following nothing")
		<-ctx.Done()
		return nil
	}
	f := newDockerFollower(c, stateDir, out)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	save := time.NewTicker(15 * time.Second)
	defer save.Stop()
	for {
		if err := f.scan(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			f.save()
			return nil
		case <-save.C:
			f.save()
		case <-t.C:
		}
	}
}

func (f *dockerFollower) save() {
	if f.state == "" {
		return
	}
	f.mu.Lock()
	b, _ := json.Marshal(f.since)
	f.mu.Unlock()
	_ = writeFileAtomic(f.state, b)
}

type dockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

func (f *dockerFollower) scan(ctx context.Context) error {
	var cs []dockerContainer
	path := "/containers/json"
	if len(f.c.Labels) > 0 {
		b, _ := json.Marshal(map[string][]string{"label": container.LabelFilter(f.c.Labels)})
		path += "?" + url.Values{"filters": {string(b)}}.Encode()
	}
	resp, err := f.get(ctx, path)
	if err != nil {
		return err
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&cs)
	resp.Body.Close()
	if err != nil {
		return errors.New("docker: malformed container list")
	}
	for _, c := range cs {
		if !container.HasLabels(c.Labels, f.c.Labels) { // guards an engine that ignored the filter
			continue
		}
		f.mu.Lock()
		run := f.running[c.ID]
		f.running[c.ID] = true
		f.mu.Unlock()
		if !run {
			go f.follow(ctx, c)
		}
	}
	return nil
}

func (f *dockerFollower) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, errors.New("docker: engine unreachable")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("docker: %s: HTTP %d", path, resp.StatusCode)
	}
	return resp, nil
}

func (f *dockerFollower) follow(ctx context.Context, c dockerContainer) {
	defer func() {
		f.mu.Lock()
		delete(f.running, c.ID)
		f.mu.Unlock()
	}()
	var info struct {
		Config struct{ Tty bool } `json:"Config"`
	}
	if resp, err := f.get(ctx, "/containers/"+url.PathEscape(c.ID)+"/json"); err == nil {
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info)
		resp.Body.Close()
	}
	f.mu.Lock()
	since := f.since[c.ID]
	f.mu.Unlock()
	if since == 0 {
		since = time.Now().UnixNano() // a container seen for the first time starts now
	}
	q := fmt.Sprintf("/containers/%s/logs?follow=1&stdout=1&stderr=1&timestamps=1&since=%d.%09d",
		url.PathEscape(c.ID), since/1e9, since%1e9)
	resp, err := f.get(ctx, q)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	name := strings.TrimPrefix(strings.Join(c.Names, ","), "/")
	attrs := map[string]string{"container.id": c.ID, "container.name": name, "container.image.name": c.Image}
	emit := func(stream, line string) {
		ts, body, ok := strings.Cut(line, " ")
		at, err := time.Parse(time.RFC3339Nano, ts)
		if !ok || err != nil {
			at, body = time.Now(), line
		}
		if at.UnixNano() <= since { // the API's since is inclusive
			return
		}
		f.out.Log(Severity(body), body, sink.With(attrs, "log.iostream", stream), at)
		f.mu.Lock()
		f.since[c.ID] = at.UnixNano()
		f.mu.Unlock()
	}
	if info.Config.Tty {
		readLines(resp.Body, func(l string) { emit("stdout", l) })
		return
	}
	_ = demux(resp.Body, emit)
}

func readLines(r io.Reader, fn func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fn(sc.Text())
	}
}

// demux reads Docker's multiplexed stream: 8-byte headers (stream, 0, 0, 0, size BE) + payload.
func demux(r io.Reader, emit func(stream, line string)) error {
	br := bufio.NewReader(r)
	var hdr [8]byte
	partial := map[byte]string{}
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if n > 1<<20 {
			return errors.New("docker: frame too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		data := partial[hdr[0]] + string(buf)
		for {
			line, rest, ok := strings.Cut(data, "\n")
			if !ok {
				break
			}
			emit(stream, line)
			data = rest
		}
		partial[hdr[0]] = data
	}
}
