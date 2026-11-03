package custom

// Automatic target distribution between agents (CFT-A21). Agents that share one scrape config
// learn the live peer set from DNS (a Kubernetes headless service lists only ready pods) or a
// static list, and each scrapes the targets whose rendezvous hash over the peers picks it. When
// a peer joins or leaves, only the targets of that peer move. No gossip protocol and no leader:
// every agent computes the same owner from the same peer list.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sort"
	"sync/atomic"
	"time"
)

// ClusterConfig names the peers. PeersDNS is resolved to A/AAAA records every Refresh (default
// 15 s); Peers is a static list instead. Self is this agent's address among them (default
// $POD_IP, else the first local interface address found in the peer list).
type ClusterConfig struct {
	PeersDNS string   `json:"peers_dns"`
	Peers    []string `json:"peers"`
	Self     string   `json:"self"`
	Refresh  string   `json:"refresh_interval"`
}

func (c ClusterConfig) every() time.Duration {
	return parseDur(c.Refresh, 15*time.Second, 5*time.Second, 5*time.Minute)
}

type cluster struct {
	self  string
	peers atomic.Pointer[[]string] // sorted, includes self
}

// lookupPeers is replaceable in tests.
var lookupPeers = func(ctx context.Context, name string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP.String())
	}
	return out, err
}

func localAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

// owner is the rendezvous (highest random weight) choice of target over peers.
func owner(target string, peers []string) string {
	best, bestW := "", uint64(0)
	for _, p := range peers {
		h := sha256.Sum256([]byte(p + "\x00" + target))
		if w := binary.BigEndian.Uint64(h[:8]); best == "" || w > bestW {
			best, bestW = p, w
		}
	}
	return best
}

func (cl *cluster) owns(target string) bool {
	p := cl.peers.Load()
	if p == nil || len(*p) == 0 {
		return true // no membership yet: scrape rather than drop (duplicates dedupe downstream)
	}
	return owner(target, *p) == cl.self
}

func (cl *cluster) refresh(ctx context.Context, c ClusterConfig) int {
	peers := append([]string(nil), c.Peers...)
	if c.PeersDNS != "" {
		got, err := lookupPeers(ctx, c.PeersDNS)
		if err != nil || len(got) == 0 {
			return -1 // keep the last known peer set
		}
		peers = got
	}
	seen := map[string]bool{cl.self: true}
	list := []string{cl.self}
	for _, p := range peers {
		if !seen[p] {
			seen[p] = true
			list = append(list, p)
		}
	}
	sort.Strings(list)
	cl.peers.Store(&list)
	return len(list)
}

// startCluster resolves self, does a first membership refresh and keeps it fresh, reporting
// `wt_cluster_peers` so a split cluster is visible.
func startCluster(ctx context.Context, c ClusterConfig, out Sink) (*cluster, error) {
	if c.PeersDNS == "" && len(c.Peers) == 0 {
		return nil, errors.New("cluster: peers_dns or peers required")
	}
	cl := &cluster{self: c.Self}
	if cl.self == "" {
		cl.self = os.Getenv("POD_IP")
	}
	if cl.self == "" {
		local := localAddrs()
		cands := c.Peers
		if c.PeersDNS != "" {
			cands, _ = lookupPeers(ctx, c.PeersDNS)
		}
		for _, p := range cands {
			if local[p] {
				cl.self = p
				break
			}
		}
	}
	if cl.self == "" {
		return nil, errors.New("cluster: cannot tell this agent's address; set cluster.self or POD_IP")
	}
	cl.refresh(ctx, c)
	go func() {
		t := time.NewTicker(c.every())
		defer t.Stop()
		for {
			if n := cl.refresh(ctx, c); n > 0 {
				out.Gauge("wt_cluster_peers", "", float64(n), map[string]string{"self": cl.self}, time.Now())
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return cl, nil
}

// JoinCluster starts membership for a non-scrape user (cluster checks) and returns the owner
// test: owns(key) is true on exactly one live peer for every key.
func JoinCluster(ctx context.Context, c ClusterConfig, out Sink) (func(string) bool, error) {
	cl, err := startCluster(ctx, c, out)
	if err != nil {
		return nil, err
	}
	return cl.owns, nil
}
