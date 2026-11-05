//go:build linux

package net

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	stdnet "net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	agentebpf "github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
	"github.com/watchtowerobservability/watchtower-agent/agent/ebpf/trace"
	"github.com/watchtowerobservability/watchtower-agent/agent/k8s"
)

const connEvSize = 96 // struct conn_ev in bpf/tcp.bpf.c

var containerRe = regexp.MustCompile(`[0-9a-f]{64}`)

// decodeConn reads a struct conn_ev.
func decodeConn(b []byte) (Conn, bool) {
	if len(b) < connEvSize {
		return Conn{}, false
	}
	le := binary.LittleEndian
	addr := func(raw []byte, v6 bool) netip.Addr {
		if v6 {
			return netip.AddrFrom16([16]byte(raw[:16])).Unmap()
		}
		return netip.AddrFrom4([4]byte(raw[:4]))
	}
	v6 := b[88] == 1
	return Conn{
		BytesSent: le.Uint64(b[8:]), BytesRecv: le.Uint64(b[16:]), ConnectNs: le.Uint64(b[24:]), Cgroup: le.Uint64(b[32:]),
		Retrans: le.Uint32(b[40:]), SRTTus: le.Uint32(b[44:]), PID: le.Uint32(b[48:]),
		LPort: le.Uint16(b[52:]), RPort: le.Uint16(b[54:]),
		Src: addr(b[56:72], v6), Dst: addr(b[72:88], v6),
		Failed: b[89] == 1, Reset: b[90] == 1, Active: b[91] == 1,
	}, true
}

// Run loads tcp.bpf.c and exports TCP and DNS telemetry every interval until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out Exporter) error {
	cfg, err := ParseConfig(raw)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		<-ctx.Done()
		return nil
	}
	if err := agentebpf.Preflight(); err != nil {
		return err
	}
	window, _ := cfg.Window()
	spec, err := agentebpf.LoadSpec(cfg.ObjectDir, "tcp")
	if err != nil {
		return err
	}
	spec.Maps["conn_events"].MaxEntries = uint32(cfg.RingBufferKB) << 10
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()
	l1, err := link.Tracepoint("sock", "inet_sock_set_state", coll.Programs["set_state"], nil)
	if err != nil {
		return err
	}
	defer l1.Close()
	if l2, err := link.Tracepoint("tcp", "tcp_receive_reset", coll.Programs["receive_reset"], nil); err == nil {
		defer l2.Close()
	} else {
		slog.Warn("ebpf_net: tcp_receive_reset tracepoint unavailable, reset counts will be zero", "err", err)
	}
	rd, err := ringbuf.NewReader(coll.Maps["conn_events"])
	if err != nil {
		return err
	}
	defer rd.Close()

	conns := make(chan Conn, 1024)
	go readConns(ctx, rd, trace.NewLimiter(cfg.MaxEventsPerSec), conns)
	var dns chan dnsPacket
	if cfg.WantDNS() {
		dns = make(chan dnsPacket, 1024)
		go func() {
			if err := captureDNS(ctx, dns); err != nil {
				slog.Warn("ebpf_net: DNS capture stopped", "err", err)
			}
		}()
	}
	zones := NewZones(cfg.Zone, cfg.ZonePrefixes)
	if cfg.ZonesFromK8s {
		go zones.followK8s(ctx)
	}
	return loop(ctx, window, newProcResolver(), zones, coll.Maps["drops"], conns, dns, out)
}

func readConns(ctx context.Context, rd *ringbuf.Reader, lim *trace.Limiter, out chan<- Conn) {
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if c, ok := decodeConn(rec.RawSample); ok && lim.Allow(time.Now()) {
			select {
			case out <- c:
			default:
			}
		}
	}
}

func loop(ctx context.Context, window time.Duration, res Resolver, zones *Zones, drops *ebpf.Map, conns <-chan Conn, dns <-chan dnsPacket, out Exporter) error {
	agg := NewAggregator(res)
	agg.Zones = zones
	dt := NewDNSTracker()
	tk := time.NewTicker(window)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case c := <-conns:
			agg.Add(c)
		case p := <-dns:
			dt.Observe(p.msg, p.cport, p.at)
		case now := <-tk.C:
			agg.Flush(out, now)
			dt.Flush(out, now)
			var d uint64
			if drops.Lookup(uint32(0), &d) == nil && d > 0 {
				out.Sum("wt.net.events_dropped", "{event}", float64(d), map[string]string{"module": "ebpf_net"}, now)
			}
		}
	}
}

// procResolver names workloads from /proc: container/<id12> or the process name, matching the
// service names the eBPF profiler uses, or <namespace>/<pod> when the k8s_node module knows the
// container (k8s.ContainerByID), with the pod and workload as flow attributes.
type procResolver struct {
	names     map[uint32]string
	labels    map[string]map[string]string // workload name -> container/pod attributes
	listeners atomic.Pointer[map[uint16]string]
	local     map[netip.Addr]bool
	refreshed time.Time
}

func newProcResolver() *procResolver {
	r := &procResolver{names: map[uint32]string{}, labels: map[string]map[string]string{}}
	r.refresh()
	return r
}

func (r *procResolver) refresh() {
	r.refreshed = time.Now()
	r.local = map[netip.Addr]bool{}
	if as, err := stdnet.InterfaceAddrs(); err == nil {
		for _, a := range as {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				r.local[p.Addr()] = true
			}
		}
	}
	m := listenPorts()
	ports := map[uint16]string{}
	for port, pid := range m {
		ports[port] = r.Workload(pid, 0)
	}
	r.listeners.Store(&ports)
}

func (r *procResolver) stale() {
	if time.Since(r.refreshed) > 30*time.Second {
		clear(r.names) // pids get reused
		if len(r.labels) > 5000 {
			clear(r.labels) // names stay stable for flushes of live edges; only cap churned pods
		}
		r.refresh()
	}
}

func (r *procResolver) Workload(pid uint32, _ uint64) string {
	if n, ok := r.names[pid]; ok {
		return n
	}
	dir := "/proc/" + strconv.Itoa(int(pid))
	name := "unknown"
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		name = strings.TrimSpace(string(b))
	}
	if cg, err := os.ReadFile(dir + "/cgroup"); err == nil {
		if id := containerRe.FindString(string(cg)); id != "" {
			name = "container/" + id[:12]
			labels := map[string]string{"container.id": id}
			if ref, ok := k8s.ContainerByID(id); ok {
				name = ref.Namespace + "/" + ref.Pod
				labels["k8s.namespace.name"], labels["k8s.pod.name"], labels["k8s.container.name"] = ref.Namespace, ref.Pod, ref.Container
				if ref.Workload != "" {
					labels["k8s.workload"] = ref.Workload
				}
			}
			r.labels[name] = labels
		}
	}
	r.names[pid] = name
	return name
}

// Labels are the container and pod attributes of a workload name Workload returned.
func (r *procResolver) Labels(name string) map[string]string { return r.labels[name] }

func (r *procResolver) Listener(port uint16) string {
	r.stale()
	return (*r.listeners.Load())[port]
}

func (r *procResolver) IsLocal(a netip.Addr) bool { return a.IsLoopback() || r.local[a] }

// listenPorts maps listening TCP ports of the host network namespace to the owning pid.
func listenPorts() map[uint16]uint32 {
	inodes := map[uint64]uint16{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan()
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 || fl[3] != "0A" { // LISTEN
				continue
			}
			_, p, ok := strings.Cut(fl[1], ":")
			port, err := strconv.ParseUint(p, 16, 16)
			ino, err2 := strconv.ParseUint(fl[9], 10, 64)
			if ok && err == nil && err2 == nil {
				inodes[ino] = uint16(port)
			}
		}
		fh.Close()
	}
	out := map[uint16]uint32{}
	fds, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	for _, fd := range fds {
		l, err := os.Readlink(fd)
		if err != nil {
			continue
		}
		ino, ok := trace.SocketInode(l)
		if !ok {
			continue
		}
		if port, ok := inodes[ino]; ok {
			pid, _ := strconv.ParseUint(strings.Split(fd, "/")[2], 10, 32)
			out[port] = uint32(pid)
		}
	}
	return out
}
