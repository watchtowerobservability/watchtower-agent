//go:build linux

package runtimesec

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	agentebpf "github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
	"github.com/watchtowerobservability/watchtower-agent/agent/ebpf/trace"
	"github.com/watchtowerobservability/watchtower-agent/agent/k8s"
)

// embedded holds runtimesec_bpfel.o built by `make ebpf-gen` (bpf/runtimesec.bpf.c). The committed
// tree carries only a placeholder (objects/.gitignore ignores *.o), so a binary built without that
// step embeds no object and loadSpec falls back to cfg.ObjectDir on disk.
//
//go:embed objects
var embedded embed.FS

var containerRe = regexp.MustCompile(`[0-9a-f]{64}`)

// probe maps a collection program to the tracepoint it attaches to. The program names mirror the
// SEC()-tagged functions in bpf/runtimesec.bpf.c.
var probes = []struct{ prog, group, name string }{
	{"enter_execve", "syscalls", "sys_enter_execve"},
	{"enter_openat", "syscalls", "sys_enter_openat"},
	{"enter_connect", "syscalls", "sys_enter_connect"},
}

// loadSpec loads the runtimesec collection, preferring the embedded object and falling back to disk.
func loadSpec(dir string) (*ebpf.CollectionSpec, error) {
	const file = "runtimesec_bpfel.o"
	if b, err := embedded.ReadFile("objects/" + file); err == nil {
		return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(b))
	}
	spec, err := ebpf.LoadCollectionSpec(dir + "/" + file)
	if err != nil {
		return nil, fmt.Errorf("%w (build and embed the objects with `make ebpf-gen`, or install them into object_dir)", err)
	}
	return spec, nil
}

// loadAndRun loads the probes, attaches them, and feeds matched events to the emitter until ctx ends.
func loadAndRun(ctx context.Context, cfg Config, pol Policy, em *Emitter, out Sink, host string) error {
	if err := agentebpf.Preflight(); err != nil {
		return err
	}
	spec, err := loadSpec(cfg.ObjectDir)
	if err != nil {
		return err
	}
	if m := spec.Maps["events"]; m != nil {
		m.MaxEntries = uint32(cfg.RingBufferKB) << 10
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()
	for _, p := range probes {
		prog := coll.Programs[p.prog]
		if prog == nil {
			return fmt.Errorf("runtime_security: object has no program %q (rebuild with `make ebpf-gen`)", p.prog)
		}
		l, err := link.Tracepoint(p.group, p.name, prog, nil)
		if err != nil {
			return fmt.Errorf("runtime_security: attach %s/%s: %w", p.group, p.name, err)
		}
		defer l.Close()
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return err
	}
	defer rd.Close()
	go func() { <-ctx.Done(); rd.Close() }()

	out.Log("info", fmt.Sprintf("runtime_security active with %d policy rules, %d eBPF probes", len(pol.Rules), len(probes)),
		map[string]string{"wt.security.source": "runtime_security", "host.name": host}, time.Now())

	res := newResolver()
	lim := trace.NewLimiter(cfg.MaxEventsPerSec)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}
		ev, ok := DecodeEvent(rec.RawSample)
		if !ok {
			continue
		}
		ev.Service, ev.InContainer = res.resolve(ev.PID, ev.Comm)
		for _, h := range pol.Match(ev) {
			if lim.Allow(time.Now()) {
				em.Signal(h.Rule, ev.Service, h.Detail)
			}
		}
	}
}

// resolver names the workload behind a pid from its cgroup, matching the service names ebpf_net uses:
// <namespace>/<pod> (or the controlling workload) when the k8s node agent knows the container,
// container/<id12> for a bare container, else the process name. It caches by pid (pids get reused,
// so entries are cleared every 30s).
type resolver struct {
	names     map[uint32]string
	container map[uint32]bool
	refreshed time.Time
}

func newResolver() *resolver {
	return &resolver{names: map[uint32]string{}, container: map[uint32]bool{}, refreshed: time.Now()}
}

func (r *resolver) resolve(pid uint32, comm string) (string, bool) {
	if time.Since(r.refreshed) > 30*time.Second {
		clear(r.names)
		clear(r.container)
		r.refreshed = time.Now()
	}
	if n, ok := r.names[pid]; ok {
		return n, r.container[pid]
	}
	name, inContainer := comm, false
	if cg, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup"); err == nil {
		if id := containerRe.FindString(string(cg)); id != "" {
			inContainer = true
			name = "container/" + id[:12]
			if ref, ok := k8s.ContainerByID(id); ok {
				if ref.Workload != "" {
					name = ref.Workload
				} else {
					name = ref.Namespace + "/" + ref.Pod
				}
			}
		}
	}
	name = strings.TrimSpace(name)
	r.names[pid] = name
	r.container[pid] = inContainer
	return name, inContainer
}
