package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// DockerConfig is the docker module's config: the Engine API endpoint, local-file only.
// Socket is a unix socket path (default /var/run/docker.sock) or, with URL, a TCP endpoint.
type DockerConfig struct {
	Base
	Socket string `json:"socket"`
	URL    string `json:"url"`
}

func (c *DockerConfig) check() error {
	if c.URL != "" && !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
		return errors.New("docker: url must be http(s)")
	}
	if c.Socket == "" && c.URL == "" {
		c.Socket = "/var/run/docker.sock" // shortcut: no Windows named pipe, use url with the TCP API there
	}
	return nil
}

type dockerContainer struct {
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

// Docker lists containers through the Engine API and reports engine-level counts by state and
// one `docker.container.up` series per container (at most 500).
func Docker(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &DockerConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	hc, base := httpClient, strings.TrimRight(c.URL, "/")
	if c.Socket != "" {
		base = "http://docker"
		hc = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", c.Socket)
			},
		}}
	}
	return Loop(ctx, "docker", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/containers/json?all=1&limit=500", nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return errors.New(sink.Truncate(err.Error(), 200))
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("docker: HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return err
		}
		return EmitDocker(out, b, now)
	})
}

// EmitDocker parses a /containers/json body.
func EmitDocker(out sink.Sink, body []byte, now time.Time) error {
	var cs []dockerContainer
	if err := json.Unmarshal(body, &cs); err != nil {
		return fmt.Errorf("docker: not a container list: %w", err)
	}
	counts := map[string]float64{"running": 0, "paused": 0, "exited": 0, "restarting": 0}
	for _, ct := range cs {
		name := strings.TrimPrefix(strings.Join(ct.Names, ","), "/")
		up := 0.0
		if ct.State == "running" {
			up = 1
		}
		counts[ct.State]++
		out.Gauge("docker.container.up", "1", up, map[string]string{"container": name, "image": ct.Image, "state": ct.State}, now)
	}
	for state, n := range counts {
		out.Gauge("docker.containers", "{containers}", n, map[string]string{"state": state}, now)
	}
	return nil
}
