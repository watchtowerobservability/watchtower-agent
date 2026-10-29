package integrations

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Socket is one listening TCP socket and the process that owns it.
type Socket struct {
	Port    int
	Process string
}

// Detected is a manifest matched by a listening socket.
type Detected struct {
	Integration string
	Port        int
	Process     string
}

const maxSockets = 200

// Match returns, per socket, the first manifest (in name order) whose discovery lists the
// socket's port or process name (case-insensitive, `.exe` ignored). A process name wins over a
// port, so a service on a non-standard port is still found.
func Match(ms []*Manifest, socks []Socket) []Detected {
	var out []Detected
	for _, s := range socks {
		proc := strings.TrimSuffix(strings.ToLower(s.Process), ".exe")
		for _, byProc := range []bool{true, false} {
			i := slices.IndexFunc(ms, func(m *Manifest) bool {
				if byProc {
					return proc != "" && slices.ContainsFunc(m.Discovery.ProcessNames, func(n string) bool {
						return strings.ToLower(n) == proc
					})
				}
				return slices.Contains(m.Discovery.Ports, s.Port)
			})
			if i >= 0 {
				out = append(out, Detected{Integration: ms[i].Name, Port: s.Port, Process: s.Process})
				break
			}
		}
	}
	return out
}

// ListenConfig is the listen module's config. ManifestsDir is local-file only.
type ListenConfig struct {
	Base
	// ManifestsDir (optional) lets the agent name the matched integration itself; the API
	// matches against its own copy either way.
	ManifestsDir string `json:"manifests_dir"`
}

func (*ListenConfig) check() error { return nil }

// Listen reports `wt.agent.listening` (value 1; port, process, and integration when matched)
// for up to 200 listening TCP sockets every 60 s, so the API can say "postgres on :5432 on
// host X".
func Listen(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &ListenConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	var ms []*Manifest
	if c.ManifestsDir != "" {
		var err error
		if ms, err = LoadFS(os.DirFS(c.ManifestsDir)); err != nil {
			return err
		}
	}
	return Loop(ctx, "listen", c.Base, 60*time.Second, out, func(ctx context.Context, now time.Time) error {
		socks, err := ListeningSockets(ctx)
		if err != nil {
			return err
		}
		matched := map[int]string{}
		for _, d := range Match(ms, socks) {
			matched[d.Port] = d.Integration
		}
		for _, s := range socks {
			a := map[string]string{"port": strconv.Itoa(s.Port), "process": s.Process}
			if m, ok := matched[s.Port]; ok {
				a["integration"] = m
			}
			out.Gauge("wt.agent.listening", "1", 1, a, now)
		}
		return nil
	})
}

// ListeningSockets lists TCP sockets in LISTEN state with their process names, by port.
func ListeningSockets(ctx context.Context) ([]Socket, error) {
	conns, err := gnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var out []Socket
	for _, c := range conns {
		if c.Status != "LISTEN" || c.Laddr.Port == 0 || seen[int(c.Laddr.Port)] {
			continue
		}
		seen[int(c.Laddr.Port)] = true
		s := Socket{Port: int(c.Laddr.Port)}
		if c.Pid > 0 {
			if p, err := process.NewProcessWithContext(ctx, c.Pid); err == nil {
				if n, err := p.NameWithContext(ctx); err == nil {
					s.Process = path.Base(n)
				}
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	if len(out) > maxSockets {
		out = out[:maxSockets]
	}
	return out, nil
}
