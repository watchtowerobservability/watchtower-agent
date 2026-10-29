// Package net is the wt-agent module `ebpf_net` (INF-038): per-connection TCP metrics and DNS
// telemetry from eBPF, aggregated per (src workload, dst workload, port) every interval. Linux
// only; other platforms compile stubs. It feeds the infra service graph through the
// server.address attribute.
package net

import (
	"net/netip"
	"sort"
	"strconv"
	"time"
)

// Conn is one closed TCP connection as reported by tcp.bpf.c.
type Conn struct {
	Src, Dst     netip.Addr // local and remote end as seen by the kernel
	LPort, RPort uint16
	BytesSent    uint64
	BytesRecv    uint64
	Retrans      uint32
	SRTTus       uint32
	ConnectNs    uint64
	Failed       bool // SYN_SENT -> CLOSE
	Reset        bool
	Active       bool // this host opened it (pid is the owner)
	PID          uint32
	Cgroup       uint64
}

// Resolver names workloads. Implementations use the cgroup id and pid for local processes and
// the listening port table for servers on this host.
type Resolver interface {
	Workload(pid uint32, cgroup uint64) string // container or process name of a local owner
	Listener(port uint16) string               // workload listening on a local port, "" if unknown
	IsLocal(a netip.Addr) bool
}

// Exporter is the part of the agent's exporter the module writes to.
type Exporter interface {
	Gauge(name, unit string, value float64, attrs map[string]string, at time.Time)
	Sum(name, unit string, value float64, attrs map[string]string, at time.Time)
	Log(severity, body string, attrs map[string]string, at time.Time)
}

type edgeKey struct {
	src, dst string
	port     uint16
	addr     string // server.address
}

type edge struct {
	sent, recv, retrans, resets, conns, failures float64 // cumulative
	rttSum, rttN, connSum, connN                 float64 // this interval only
	dirty                                        bool
}

const (
	maxEdges    = 10_000
	maxFailLogs = 50
)

// Aggregator folds connections into edges.
type Aggregator struct {
	res      Resolver
	edges    map[edgeKey]*edge
	failLogs []Conn
	Dropped  uint64 // connections ignored because the edge table was full
}

// NewAggregator returns an empty aggregator.
func NewAggregator(r Resolver) *Aggregator {
	return &Aggregator{res: r, edges: map[edgeKey]*edge{}}
}

// Add records one connection. A passive connection whose peer is on this host is skipped: its
// active twin is reported by the owning process.
func (a *Aggregator) Add(c Conn) {
	var k edgeKey
	switch {
	case c.Active:
		k.src = a.res.Workload(c.PID, c.Cgroup)
		k.port = c.RPort
		k.addr = c.Dst.String()
		k.dst = a.dstName(c.Dst, c.RPort)
	default:
		if a.res.IsLocal(c.Dst) {
			return
		}
		k.src = c.Dst.String()
		k.port = c.LPort
		k.addr = c.Src.String()
		k.dst = a.res.Listener(c.LPort)
		if k.dst == "" {
			k.dst = c.Src.String()
		}
	}
	e := a.edges[k]
	if e == nil {
		if len(a.edges) >= maxEdges {
			a.Dropped++
			return
		}
		e = &edge{}
		a.edges[k] = e
	}
	e.dirty = true
	e.conns++
	e.sent += float64(c.BytesSent)
	e.recv += float64(c.BytesRecv)
	e.retrans += float64(c.Retrans)
	if c.Reset {
		e.resets++
	}
	if c.Failed {
		e.failures++
		if len(a.failLogs) < maxFailLogs {
			a.failLogs = append(a.failLogs, c)
		}
	}
	if c.SRTTus > 0 {
		e.rttSum += float64(c.SRTTus) / 1e6
		e.rttN++
	}
	if c.ConnectNs > 0 {
		e.connSum += float64(c.ConnectNs) / 1e9
		e.connN++
	}
}

func (a *Aggregator) dstName(dst netip.Addr, port uint16) string {
	if a.res.IsLocal(dst) {
		if n := a.res.Listener(port); n != "" {
			return n
		}
	}
	return dst.String()
}

// Flush exports every edge touched since the last flush. Counters are cumulative.
func (a *Aggregator) Flush(out Exporter, at time.Time) {
	keys := make([]edgeKey, 0, len(a.edges))
	for k, e := range a.edges {
		if e.dirty {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].src+keys[i].dst < keys[j].src+keys[j].dst })
	for _, k := range keys {
		e := a.edges[k]
		at2 := map[string]string{
			"src.workload": k.src, "dst.workload": k.dst,
			"server.port": strconv.Itoa(int(k.port)), "server.address": k.addr,
		}
		out.Sum("wt.net.tcp.bytes_sent", "By", e.sent, at2, at)
		out.Sum("wt.net.tcp.bytes_received", "By", e.recv, at2, at)
		out.Sum("wt.net.tcp.retransmits", "{packet}", e.retrans, at2, at)
		out.Sum("wt.net.tcp.resets", "{connection}", e.resets, at2, at)
		out.Sum("wt.net.tcp.connections", "{connection}", e.conns, at2, at)
		out.Sum("wt.net.tcp.connect_failures", "{connection}", e.failures, at2, at)
		if e.rttN > 0 {
			out.Gauge("wt.net.tcp.rtt", "s", e.rttSum/e.rttN, at2, at)
		}
		if e.connN > 0 {
			out.Gauge("wt.net.tcp.connect_latency", "s", e.connSum/e.connN, at2, at)
		}
		e.dirty, e.rttSum, e.rttN, e.connSum, e.connN = false, 0, 0, 0, 0
	}
	for _, c := range a.failLogs {
		out.Log("WARN", "tcp connection failed", map[string]string{
			"src.workload": a.res.Workload(c.PID, c.Cgroup), "server.address": c.Dst.String(),
			"server.port": strconv.Itoa(int(c.RPort)),
		}, at)
	}
	a.failLogs = a.failLogs[:0]
}
