package main

// Live process, container and connection view (INF-022): `live_processes` samples the process table and
// the host's TCP/UDP sockets every interval (default 2 s) only while a live tap of this module is
// open (POST .../fleet/agents/{id}/tap {module: "live_processes"}), and hands the frames to the
// tap alone: nothing is exported to the gateway. Command lines are never read. Opt-in: the
// agent's own file must define the module with enabled: true.

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/watchtowerobservability/watchtower-agent/agent/commands"
	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/host"
)

const (
	liveModuleName  = "live_processes"
	liveProcesses   = 25 // rows per frame, so a 60 s tap of 2 s frames stays under tapMaxItems
	liveConnections = 15
)

type liveModule struct{ toggle }

func (liveModule) Name() string { return liveModuleName }

// liveConn is one socket as the view shows it.
type liveConn struct {
	PID           int32
	Proto, Status string
	Local, Remote string
}

type liveSource struct {
	procs func() ([]commands.ProcessInfo, error)
	conns func(ctx context.Context) ([]liveConn, error)
	ctrs  func(ctx context.Context) ([]liveCtr, error) // nil: no container rows
}

func readProcs() ([]commands.ProcessInfo, error) {
	ps, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make([]commands.ProcessInfo, 0, len(ps))
	for _, p := range ps {
		i := commands.ProcessInfo{PID: p.Pid}
		i.Name, _ = p.Name()
		i.User, _ = p.Username()
		if t, err := p.Times(); err == nil {
			i.CPUSecs = t.User + t.System
		}
		if m, err := p.MemoryInfo(); err == nil && m != nil {
			i.RSS = m.RSS
		}
		out = append(out, i)
	}
	return out, nil
}

func readConns(ctx context.Context) ([]liveConn, error) {
	cs, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, err
	}
	out := make([]liveConn, 0, len(cs))
	for _, c := range cs {
		proto := "tcp"
		if c.Type == 2 { // SOCK_DGRAM
			proto = "udp"
		}
		addr := func(a psnet.Addr) string {
			if a.IP == "" {
				return ""
			}
			return a.IP + ":" + strconv.FormatUint(uint64(a.Port), 10)
		}
		out = append(out, liveConn{PID: c.Pid, Proto: proto, Status: c.Status, Local: addr(c.Laddr), Remote: addr(c.Raddr)})
	}
	return out, nil
}

// liveFrame turns two process samples dt apart into tap items: the busiest processes by CPU
// share since the previous sample, then established connections first.
func liveFrame(prev map[int32]float64, cur []commands.ProcessInfo, conns []liveConn, dt time.Duration, at time.Time) []tapItem {
	type row struct {
		p   commands.ProcessInfo
		pct float64
	}
	rows := make([]row, 0, len(cur))
	names := map[int32]string{}
	for _, p := range cur {
		names[p.PID] = p.Name
		pct := 0.0
		if old, ok := prev[p.PID]; ok && dt > 0 && p.CPUSecs >= old {
			pct = (p.CPUSecs - old) / dt.Seconds() * 100
		}
		rows = append(rows, row{p, pct})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].pct != rows[j].pct {
			return rows[i].pct > rows[j].pct
		}
		return rows[i].p.RSS > rows[j].p.RSS
	})
	ms := at.UnixMilli()
	var out []tapItem
	for _, r := range rows[:min(len(rows), liveProcesses)] {
		out = append(out, tapItem{At: ms, Kind: "gauge", Name: "process.cpu.utilization", Value: r.pct, Attrs: map[string]string{
			"process.pid": strconv.Itoa(int(r.p.PID)), "process.executable.name": r.p.Name, "process.owner": r.p.User,
			"process.memory.usage": strconv.FormatUint(r.p.RSS, 10),
		}})
	}
	sort.SliceStable(conns, func(i, j int) bool { return conns[i].Status == "ESTABLISHED" && conns[j].Status != "ESTABLISHED" })
	for _, c := range conns[:min(len(conns), liveConnections)] {
		out = append(out, tapItem{At: ms, Kind: "log", Name: "connection", Attrs: map[string]string{
			"process.pid": strconv.Itoa(int(c.PID)), "process.executable.name": names[c.PID], "network.transport": c.Proto,
			"network.connection.state": c.Status, "network.local.address": c.Local, "network.peer.address": c.Remote,
		}})
	}
	return out
}

func (m liveModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	var c struct {
		Containers *bool  `json:"containers"`  // default true
		DockerHost string `json:"docker_host"` // local file only, like the container module
	}
	_ = json.Unmarshal(cfg, &c) // runLive reports a malformed config
	src := liveSource{procs: readProcs, conns: readConns}
	if c.Containers == nil || *c.Containers {
		src.ctrs = dockerLive(c.DockerHost)
	}
	return runLive(ctx, cfg, out, src)
}

func runLive(ctx context.Context, cfg json.RawMessage, out Exporter, src liveSource) error {
	var c struct {
		Enabled  *bool  `json:"enabled"`
		Interval string `json:"interval"`
	}
	if len(cfg) > 0 {
		if err := json.Unmarshal(cfg, &c); err != nil {
			return err
		}
	}
	te, ok := out.(*tapExporter)
	if c.Enabled == nil || !*c.Enabled || !ok {
		<-ctx.Done()
		return nil
	}
	tick := time.NewTicker(max(host.Duration(c.Interval, 2*time.Second, time.Second), time.Second))
	defer tick.Stop()
	var prev map[int32]float64
	var prevCtr map[string]container.Stats
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		if !te.on() {
			prev, prevCtr = nil, nil // a new tap starts with fresh CPU baselines
			continue
		}
		now := time.Now()
		procs, err := src.procs()
		if err != nil {
			continue
		}
		conns, _ := src.conns(ctx) // processes alone still make a frame
		var ctrRows []tapItem
		if src.ctrs != nil {
			if cs, err := src.ctrs(ctx); err == nil {
				first := prevCtr == nil
				ctrRows, prevCtr = containerFrame(prevCtr, cs, now)
				if first {
					ctrRows = nil // no CPU baseline yet
				}
			}
		}
		if prev != nil {
			for _, it := range append(liveFrame(prev, procs, conns, now.Sub(last), now), ctrRows...) {
				te.t.record(liveModuleName, it)
			}
		}
		prev, last = map[int32]float64{}, now
		for _, p := range procs {
			prev[p.PID] = p.CPUSecs
		}
	}
}
