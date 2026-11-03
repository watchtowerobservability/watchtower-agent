package custom

// ZooKeeper discovery (CFT-A02): serverset and nerve, whose members are znodes holding JSON.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/go-zookeeper/zk"
)

func init() {
	sdHTTPTypes["serverset"] = SDConfig.serversetSD
	sdHTTPTypes["nerve"] = SDConfig.nerveSD
}

// parseServerset reads a Finagle ServerSet member; only ALIVE members are targets.
func (c SDConfig) parseServerset(b []byte, _ string) (TargetSpec, bool) {
	var m struct {
		ServiceEndpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"serviceEndpoint"`
		Status string `json:"status"`
		Shard  int    `json:"shard"`
	}
	if json.Unmarshal(b, &m) != nil || m.ServiceEndpoint.Host == "" || m.Status != "ALIVE" {
		return TargetSpec{}, false
	}
	return TargetSpec{URL: c.scrapeURL(m.ServiceEndpoint.Host, m.ServiceEndpoint.Port), Labels: map[string]string{"shard": strconv.Itoa(m.Shard)}}, true
}

// parseNerve reads an AirBnB Nerve member.
func (c SDConfig) parseNerve(b []byte, _ string) (TargetSpec, bool) {
	var m struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		Name string `json:"name"`
	}
	if json.Unmarshal(b, &m) != nil || m.Host == "" {
		return TargetSpec{}, false
	}
	return TargetSpec{URL: c.scrapeURL(m.Host, m.Port), Labels: map[string]string{"name": m.Name}}, true
}

func (c SDConfig) serversetSD(ctx context.Context, _ *http.Client) ([]TargetSpec, error) {
	return c.zkMembers(ctx, "serverset", c.parseServerset)
}

func (c SDConfig) nerveSD(ctx context.Context, _ *http.Client) ([]TargetSpec, error) {
	return c.zkMembers(ctx, "nerve", c.parseNerve)
}

func (c SDConfig) zkMembers(ctx context.Context, kind string, parse func([]byte, string) (TargetSpec, bool)) ([]TargetSpec, error) {
	if len(c.Servers) == 0 || len(c.Paths) == 0 {
		return nil, fmt.Errorf("sd %s: servers and paths required", kind)
	}
	// zk has no context on its calls: dial with a bounded session and close when ctx ends.
	conn, _, err := zk.Connect(c.Servers, 10*time.Second, zk.WithLogInfo(false), zk.WithDialer(func(network, addr string, to time.Duration) (net.Conn, error) {
		d := net.Dialer{Timeout: to}
		return d.DialContext(ctx, network, addr)
	}))
	if err != nil {
		return nil, errors.New("sd " + kind + ": zookeeper connect failed")
	}
	defer conn.Close()
	var out []TargetSpec
	for _, p := range c.Paths {
		kids, _, err := conn.Children(p)
		if err != nil {
			return nil, fmt.Errorf("sd %s: %s: %w", kind, p, err)
		}
		for _, k := range kids {
			b, _, err := conn.Get(path.Join(p, k))
			if err != nil {
				continue // a member that just left
			}
			if t, ok := parse(b, p); ok {
				t.Labels["zk_path"] = p
				out = append(out, t)
			}
		}
	}
	return out, nil
}
