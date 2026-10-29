package netpath

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// det remembers the last routes of every target across runs of this process.
var det Detector

// newProber is replaced in tests.
var newProber = func(proto string, dst netip.AddrPort) Prober { return SocketProber{Proto: proto, Dst: dst} }

func validProto(p string) bool { return p == "" || p == "icmp" || p == ProtoTCP || p == ProtoUDP }

// socketOnce traces a TCP or UDP target (one trace per source port), emits `wt_path_up`,
// `wt_path_hops` and `wt_path_routes`, one `network.path` log with every distinct route, and one
// `network.path_change` log when the set of routes differs from the last run.
func socketOnce(ctx context.Context, t Target, out sink.Sink, at time.Time) {
	attrs := map[string]string{"path.target": t.Name, "path.host": t.Host, "path.proto": t.Proto}
	c, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(c, "ip4", t.Host)
	if err != nil || len(ips) == 0 {
		msg := "the host did not resolve to an IPv4 address"
		out.Gauge("wt_path_up", "", 0, attrs, at)
		out.Log("WARN", msg, map[string]string{"event.name": "network.path", "path.target": t.Name,
			"path.host": t.Host, "path.reached": "false", "path.error": msg}, at)
		return
	}
	port := t.Port
	if port == 0 {
		port = 443
		if t.Proto == ProtoUDP {
			port = 33434
		}
	}
	dst := netip.AddrPortFrom(ips[0].Unmap(), uint16(port))
	paths := Multipath(c, newProber(t.Proto, dst), t.MaxHops, max(t.Paths, 1), 40000)
	reached := false
	for _, p := range paths {
		reached = reached || p.Reached
	}
	out.Gauge("wt_path_up", "", b2f(reached), attrs, at)
	out.Gauge("wt_path_hops", "", float64(len(paths[0].Hops)), attrs, at)
	out.Gauge("wt_path_routes", "", float64(len(paths)), attrs, at)
	body, _ := json.Marshal(paths)
	la := map[string]string{"event.name": "network.path", "path.target": t.Name, "path.host": t.Host,
		"path.proto": t.Proto, "path.reached": boolStr(reached)}
	if cu, bad := Blame(paths[0]); bad && !reached {
		la["path.blame_ttl"], la["path.blame_addr"] = strconv.Itoa(cu.TTL), cu.Addr
	}
	out.Log("INFO", string(body), la, at)
	if ch, changed := det.Observe(t.Name, paths); changed {
		cb, _ := json.Marshal(ch)
		out.Log("WARN", string(cb), map[string]string{"event.name": "network.path_change",
			"path.target": t.Name, "path.host": t.Host}, at)
	}
}
