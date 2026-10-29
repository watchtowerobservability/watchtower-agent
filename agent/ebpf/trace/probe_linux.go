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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
func Run(ctx context.Context, raw json.RawMessage, sink Sink) error {
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
	spec, err := ebpf.LoadCollectionSpec(filepath.Join(cfg.ObjectDir, "http_bpfel.o"))
	if err != nil {
		return fmt.Errorf("%w (build the objects with `make ebpf-gen`)", err)
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				col.Flush()
				if d := col.Dropped(); d != lastDrops {
					slog.Warn("ebpf_trace: events over the rate cap dropped", "dropped_total", d)
					lastDrops = d
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
			ev.PeerAddr, ev.PeerPort = p.Addr, p.Port
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

// procNames resolves pid -> service.name from /proc/<pid>/comm (cached).
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
	n := "unknown"
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/comm"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			n = s
		}
	}
	if len(p.m) > 4096 {
		clear(p.m)
	}
	p.m[pid] = n
	return n
}
