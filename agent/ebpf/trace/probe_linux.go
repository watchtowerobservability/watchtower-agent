//go:build linux

package trace

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	agentebpf "github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
)

const evSize = 24 + 512 // struct ev in bpf/trace.h

var syscallProbes = map[string]string{
	"enter_write": "sys_enter_write", "enter_sendto": "sys_enter_sendto",
	"enter_read": "sys_enter_read", "enter_recvfrom": "sys_enter_recvfrom",
	"exit_read": "sys_exit_read", "exit_recvfrom": "sys_exit_recvfrom",
}

// Run loads the probes and turns captured heads into spans until ctx ends. It returns after
// ctx ends (or a preflight/load error); the module is idle when not enabled.
func Run(ctx context.Context, raw json.RawMessage, sink Sink, stats Stats, metric Metric) error {
	var readErrs atomic.Uint64
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
	var closers []func()
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	spec, err := agentebpf.LoadSpec(cfg.ObjectDir, "http")
	if err != nil {
		return err
	}
	spec.Maps["events"].MaxEntries = uint32(cfg.RingBufferKB) << 10
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	closers = append(closers, coll.Close)
	for prog, tp := range syscallProbes {
		l, err := link.Tracepoint("syscalls", tp, coll.Programs[prog], nil)
		if err != nil {
			return fmt.Errorf("attach %s: %w", tp, err)
		}
		closers = append(closers, func() { l.Close() })
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	closers = append(closers, func() { rd.Close() })

	if cfg.WantTLS() {
		t, err := newTLSAttacher(cfg, coll.Maps["events"])
		if err != nil {
			slog.Warn("ebpf_trace: TLS probes unavailable, plaintext only", "err", err)
		} else {
			closers = append(closers, t.close)
			go t.loop(ctx)
		}
	}

	col := NewCollector(cfg.MaxEventsPerSec, newProcNames().name, sink)
	col.Metric = metric
	col.RED = cfg.WantMetrics()
	col.NoSpans = !cfg.WantSpans()
	if col.RED && metric == nil {
		slog.Warn("ebpf_trace: metrics mode set but the exporter cannot send histograms, no RED metrics")
	}
	col.Payload = NewPayload(cfg.PayloadRules)
	col.asm.Bodies = col.Payload != nil
	wantPorts := false
	for _, x := range append(append([]Selector(nil), cfg.Include...), cfg.Exclude...) {
		wantPorts = wantPorts || x.Port > 0
	}
	col.Sel = cfg.Selection(readProc(wantPorts))
	peers := newPeerResolver()
	self := uint32(os.Getpid())
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var lastDrops uint64
		for n := 0; ; n++ {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				col.Flush()
				if d := col.Dropped(); d != lastDrops {
					slog.Warn("ebpf_trace: events over the rate cap dropped", "dropped_total", d)
					lastDrops = d
				}
				if n%15 == 0 && stats != nil { // self metrics (CFT-E18)
					now := time.Now()
					stats("wt_ebpf_trace_events_dropped_total", float64(col.Dropped()), now)
					stats("wt_ebpf_trace_ringbuf_errors_total", float64(readErrs.Load()), now)
					stats("wt_ebpf_trace_spans_total", float64(col.Spans()), now)
					col.flushMetrics(now)
					stats("wt_ebpf_trace_processes_skipped_total", float64(col.Sel.Skipped()), now)
				}
			}
		}
	}()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				col.Flush()
				return nil
			}
			readErrs.Add(1)
			continue
		}
		ev, ok := decodeEvent(rec.RawSample)
		if !ok || ev.PID == self { // never trace the agent's own export traffic
			continue
		}
		if !ev.TLS {
			p, ok := peers.lookup(ev.PID, ev.FD)
			if !ok {
				continue // not a TCP socket
			}
			ev.PeerAddr, ev.PeerPort, ev.LocalPort = p.Addr, p.Port, p.LocalPort
		}
		col.Feed(ev)
	}
}

func decodeEvent(b []byte) (Event, bool) {
	if len(b) < evSize {
		return Event{}, false
	}
	n := int(binary.LittleEndian.Uint32(b[16:20]))
	if n > 512 {
		return Event{}, false
	}
	return Event{
		TS:   time.Now(), // the kernel clock is monotonic; span durations use arrival time
		PID:  binary.LittleEndian.Uint32(b[8:12]),
		FD:   int32(binary.LittleEndian.Uint32(b[12:16])),
		Dir:  Dir(b[20]),
		TLS:  b[21] == 1,
		Data: append([]byte(nil), b[24:24+n]...),
	}, true
}

// peerResolver maps (pid, fd) to the TCP peer through /proc, caching for a few seconds.
type peerResolver struct {
	mu    sync.Mutex
	cache map[[2]uint64]cached
}

type cached struct {
	p   Peer
	ok  bool
	exp time.Time
}

func newPeerResolver() *peerResolver { return &peerResolver{cache: map[[2]uint64]cached{}} }

func (r *peerResolver) lookup(pid uint32, fd int32) (Peer, bool) {
	k := [2]uint64{uint64(pid), uint64(uint32(fd))}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cache[k]; ok && now.Before(c.exp) {
		return c.p, c.ok
	}
	if len(r.cache) > 8192 {
		clear(r.cache)
	}
	p, ok := resolvePeer(pid, fd)
	r.cache[k] = cached{p, ok, now.Add(3 * time.Second)}
	return p, ok
}

func resolvePeer(pid uint32, fd int32) (Peer, bool) {
	dir := "/proc/" + strconv.Itoa(int(pid))
	l, err := os.Readlink(dir + "/fd/" + strconv.Itoa(int(fd)))
	if err != nil {
		return Peer{}, false
	}
	ino, ok := SocketInode(l)
	if !ok {
		return Peer{}, false
	}
	for _, f := range []string{"/net/tcp", "/net/tcp6"} { // the process's own network namespace
		fh, err := os.Open(dir + f)
		if err != nil {
			continue
		}
		m := ParseProcNetTCP(fh)
		fh.Close()
		if p, ok := m[ino]; ok {
			return p, true
		}
	}
	return Peer{}, false
}

// procNames resolves pid -> service.name (cached), see resolveService for the order.
type procNames struct {
	mu sync.Mutex
	m  map[uint32]string
}

func newProcNames() *procNames { return &procNames{m: map[uint32]string{}} }

func (p *procNames) name(pid uint32) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n, ok := p.m[pid]; ok {
		return n
	}
	n := resolveService("/proc/" + strconv.Itoa(int(pid)))
	if len(p.m) > 4096 {
		clear(p.m)
	}
	p.m[pid] = n
	return n
}

// resolveService names the service of a process at procDir, preferring a name the app or
// orchestrator declared over the process's comm (USM, D11). Order: OTEL_SERVICE_NAME, DD_SERVICE
// or service.name from OTEL_RESOURCE_ATTRIBUTES in the environment; then the k8s workload derived
// from the pod hostname; then /proc/<pid>/comm.
// shortcut: the container-label source (com.watchtower.service) and the Deployment name from the
// k8s control plane are not read here — resolving them per pid needs the container/k8s metadata
// providers plumbed into the probe; env and the hostname heuristic cover the SDK-less common case.
func resolveService(procDir string) string {
	env := readEnviron(procDir + "/environ")
	if s := first(env["OTEL_SERVICE_NAME"], env["DD_SERVICE"], resourceService(env["OTEL_RESOURCE_ATTRIBUTES"])); s != "" {
		return s
	}
	if w := k8sWorkload(env["HOSTNAME"]); w != "" {
		return w
	}
	if b, err := os.ReadFile(procDir + "/comm"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return "unknown"
}

func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// readEnviron reads /proc/<pid>/environ (NUL-separated KEY=VALUE); empty on any error.
func readEnviron(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, kv := range strings.Split(string(b), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[k] = v
		}
	}
	return out
}

// resourceService returns service.name from an OTEL_RESOURCE_ATTRIBUTES list ("k=v,k=v").
func resourceService(ra string) string {
	for _, kv := range strings.Split(ra, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.TrimSpace(k) == "service.name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// k8sWorkload derives the Deployment name from a pod hostname of the form
// <workload>-<replicaset-hash>-<pod-suffix> by stripping the two generated segments. It returns ""
// unless both trailing segments clearly match, so a plain host or StatefulSet pod falls through.
func k8sWorkload(host string) string {
	parts := strings.Split(host, "-")
	if len(parts) < 3 {
		return ""
	}
	if isPodSuffix(parts[len(parts)-1]) && isReplicaSetHash(parts[len(parts)-2]) {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return ""
}

func isPodSuffix(s string) bool {
	if len(s) != 5 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// isReplicaSetHash matches the pod-template-hash k8s adds: safe base32 (no vowels, no 0 or 1).
func isReplicaSetHash(s string) bool {
	if len(s) < 8 || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("bcdfghjklmnpqrstvwxz23456789", r) {
			return false
		}
	}
	return true
}
