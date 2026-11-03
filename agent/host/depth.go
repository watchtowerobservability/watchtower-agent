package host

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// CollectDepth adds the node_exporter-depth series: per-core and per-mode CPU time, paging and
// swap, process counts, context switches and TCP connection states.
func CollectDepth(out sink.Sink, at time.Time) {
	if ts, err := cpu.Times(true); err == nil {
		EmitCPUTimes(out, ts, at)
	}
	if s, err := mem.SwapMemory(); err == nil {
		out.Gauge("system.paging.limit", "By", float64(s.Total), nil, at)
		out.Gauge("system.paging.usage", "By", float64(s.Used), map[string]string{"state": "used"}, at)
		out.Gauge("system.paging.usage", "By", float64(s.Free), map[string]string{"state": "free"}, at)
		out.Sum("system.paging.swapped", "By", float64(s.Sin), map[string]string{"direction": "in"}, at)
		out.Sum("system.paging.swapped", "By", float64(s.Sout), map[string]string{"direction": "out"}, at)
		out.Sum("system.paging.faults", "{fault}", float64(s.PgMajFault), map[string]string{"type": "major"}, at)
		if s.PgFault >= s.PgMajFault {
			out.Sum("system.paging.faults", "{fault}", float64(s.PgFault-s.PgMajFault), map[string]string{"type": "minor"}, at)
		}
	}
	if m, err := load.Misc(); err == nil {
		out.Gauge("system.processes.count", "{process}", float64(m.ProcsRunning), map[string]string{"status": "running"}, at)
		out.Gauge("system.processes.count", "{process}", float64(m.ProcsBlocked), map[string]string{"status": "blocked"}, at)
		out.Gauge("system.processes.total", "{process}", float64(m.ProcsTotal), nil, at)
		out.Sum("system.processes.created", "{process}", float64(m.ProcsCreated), nil, at)
		out.Sum("system.cpu.context_switches", "{switch}", float64(m.Ctxt), nil, at)
	}
	if states := tcpStates(); states != nil {
		for st, n := range states {
			out.Gauge("system.network.connections", "{connection}", float64(n), map[string]string{"protocol": "tcp", "state": st}, at)
		}
	}
}

// EmitCPUTimes writes system.cpu.time per logical CPU and mode (cumulative seconds).
func EmitCPUTimes(out sink.Sink, ts []cpu.TimesStat, at time.Time) {
	for _, t := range ts {
		n := strings.TrimPrefix(t.CPU, "cpu")
		for _, m := range []struct {
			mode string
			v    float64
		}{{"user", t.User}, {"system", t.System}, {"idle", t.Idle}, {"nice", t.Nice}, {"iowait", t.Iowait},
			{"irq", t.Irq}, {"softirq", t.Softirq}, {"steal", t.Steal}} {
			out.Sum("system.cpu.time", "s", m.v, map[string]string{"cpu.logical_number": n, "cpu.mode": m.mode}, at)
		}
	}
}

// EmitDiskDepth writes operation counts, operation time, busy time and queue depth per disk.
func EmitDiskDepth(out sink.Sink, d Discovery, stats map[string]disk.IOCountersStat, at time.Time) {
	for dev, c := range stats {
		if !d.Allow(KindDisk, dev) {
			continue
		}
		r, w := map[string]string{"device": dev, "direction": "read"}, map[string]string{"device": dev, "direction": "write"}
		out.Sum("system.disk.operations", "{operation}", float64(c.ReadCount), r, at)
		out.Sum("system.disk.operations", "{operation}", float64(c.WriteCount), w, at)
		out.Sum("system.disk.operation_time", "s", float64(c.ReadTime)/1000, r, at)
		out.Sum("system.disk.operation_time", "s", float64(c.WriteTime)/1000, w, at)
		out.Sum("system.disk.merged", "{operation}", float64(c.MergedReadCount), r, at)
		out.Sum("system.disk.merged", "{operation}", float64(c.MergedWriteCount), w, at)
		dv := map[string]string{"device": dev}
		out.Sum("system.disk.io_time", "s", float64(c.IoTime)/1000, dv, at)
		out.Sum("system.disk.weighted_io_time", "s", float64(c.WeightedIO)/1000, dv, at)
		out.Gauge("system.disk.pending_operations", "{operation}", float64(c.IopsInProgress), dv, at)
	}
}

// EmitNICDepth writes packets, errors and drops per interface and direction.
func EmitNICDepth(out sink.Sink, d Discovery, nics []gnet.IOCountersStat, at time.Time) {
	for _, c := range nics {
		if !d.Allow(KindNIC, c.Name) {
			continue
		}
		rx, tx := map[string]string{"device": c.Name, "direction": "receive"}, map[string]string{"device": c.Name, "direction": "transmit"}
		out.Sum("system.network.packets", "{packet}", float64(c.PacketsRecv), rx, at)
		out.Sum("system.network.packets", "{packet}", float64(c.PacketsSent), tx, at)
		out.Sum("system.network.errors", "{error}", float64(c.Errin), rx, at)
		out.Sum("system.network.errors", "{error}", float64(c.Errout), tx, at)
		out.Sum("system.network.dropped", "{packet}", float64(c.Dropin), rx, at)
		out.Sum("system.network.dropped", "{packet}", float64(c.Dropout), tx, at)
	}
}

// tcpStateNames are the kernel's TCP states (include/net/tcp_states.h) by /proc/net/tcp code,
// named as node_exporter's tcpstat collector names them.
var tcpStateNames = map[string]string{
	"01": "established", "02": "syn_sent", "03": "syn_recv", "04": "fin_wait1", "05": "fin_wait2",
	"06": "time_wait", "07": "close", "08": "close_wait", "09": "last_ack", "0A": "listen", "0B": "closing",
}

// tcpStates counts TCP sockets by state. Linux reads /proc/net/tcp{,6} (no per-process fd walk);
// Windows asks the TCP table.
// shortcut: macOS and BSD would need lsof/sockstat per pass, so they report no TCP states; add a
// sysctl net.inet.tcp.pcblist reader when someone needs them there.
func tcpStates() map[string]int {
	switch runtime.GOOS {
	case "linux":
		counts := map[string]int{}
		ok := false
		for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			if f, err := os.Open(p); err == nil {
				ParseProcNetTCP(f, counts)
				f.Close()
				ok = true
			}
		}
		if !ok {
			return nil
		}
		return counts
	case "windows":
		cs, err := gnet.Connections("tcp")
		if err != nil {
			return nil
		}
		counts := map[string]int{}
		for _, c := range cs {
			counts[strings.ToLower(c.Status)]++
		}
		return counts
	}
	return nil
}

// ParseProcNetTCP adds the sockets of one /proc/net/tcp-format table to counts by state name.
func ParseProcNetTCP(r io.Reader, counts map[string]int) {
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		if name, ok := tcpStateNames[strings.ToUpper(f[3])]; ok {
			counts[name]++
		} else if _, err := strconv.ParseUint(f[3], 16, 8); err == nil {
			counts["unknown"]++
		}
	}
}
