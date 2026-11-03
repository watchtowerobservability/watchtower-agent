//go:build linux

package ebpf

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var containerRe = regexp.MustCompile(`[0-9a-f]{64}`)
var podRe = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)

// procResolver implements Resolver from /proc. One instance lives for one upload window, so
// its caches never go stale across pid reuse for long.
type procResolver struct {
	proc    string // /proc, overridable in tests
	host    string
	kernel  *Kallsyms
	maps    map[uint32][]Mapping
	perf    map[uint32]*PerfMap
	buildID map[string]string
	metas   map[uint32]Meta
	dotnet  bool // runtime_stacks "dotnet": ask .NET processes for a perf map
}

func newProcResolver(host string, dotnet bool) *procResolver {
	r := &procResolver{proc: "/proc", host: host, maps: map[uint32][]Mapping{}, perf: map[uint32]*PerfMap{},
		buildID: map[string]string{}, metas: map[uint32]Meta{}, kernel: &Kallsyms{}, dotnet: dotnet}
	if f, err := os.Open(filepath.Join(r.proc, "kallsyms")); err == nil {
		r.kernel = ParseKallsyms(f)
		f.Close()
	}
	return r
}

func (r *procResolver) Kernel(addr uint64) Frame {
	return Frame{Addr: addr, Name: r.kernel.Lookup(addr)}
}

func (r *procResolver) User(pid uint32, addr uint64) Frame {
	ms, ok := r.maps[pid]
	if !ok {
		if f, err := os.Open(filepath.Join(r.proc, strconv.Itoa(int(pid)), "maps")); err == nil {
			ms = ParseMaps(f)
			f.Close()
		}
		r.maps[pid] = ms
	}
	m, found := FindMapping(ms, addr)
	if !found {
		return Frame{Addr: addr}
	}
	if m.Path == "" || strings.HasPrefix(m.Path, "[") || strings.HasPrefix(m.Path, "/memfd:") {
		// anonymous executable memory: a JIT. Use the perf map when the runtime wrote one.
		if name, ok := r.perfMap(pid).Lookup(addr); ok {
			return Frame{Addr: addr, Name: name}
		}
		if r.dotnet {
			r.askDotnet(pid, ms)
		}
		return Frame{Addr: addr}
	}
	id, ok := r.buildID[m.Path]
	if !ok {
		id = BuildID(filepath.Join(r.proc, strconv.Itoa(int(pid)), "root", m.Path))
		r.buildID[m.Path] = id
	}
	return Frame{Addr: addr - m.Start + m.Offset, Module: m.Path, BuildID: id}
}

func (r *procResolver) perfMap(pid uint32) *PerfMap {
	if p, ok := r.perf[pid]; ok {
		return p
	}
	p := &PerfMap{}
	for _, path := range r.perfMapPaths(pid) {
		if f, err := os.Open(path); err == nil {
			p = ParsePerfMap(f)
			f.Close()
			break
		}
	}
	r.perf[pid] = p
	return p
}

// perfMapPaths lists where the runtime of pid writes its perf map (Python 3.12 `-X perf`, Ruby
// `--yjit-perf`, Node `--perf-basic-prof`, JVM perf-map-agent, .NET `DOTNET_PerfMapEnabled`):
// inside the process's mount namespace under its namespace pid (containers), then the host path.
func (r *procResolver) perfMapPaths(pid uint32) []string {
	dir := filepath.Join(r.proc, strconv.Itoa(int(pid)))
	var out []string
	if f, err := os.Open(filepath.Join(dir, "status")); err == nil {
		if ns, ok := NSPid(f); ok {
			out = append(out, filepath.Join(dir, "root", "tmp", fmt.Sprintf("perf-%d.map", ns)))
		}
		f.Close()
	}
	return append(out, fmt.Sprintf("/tmp/perf-%d.map", pid))
}

// dotnetAsked holds the pids already asked for a perf map, for the agent's life.
// shortcut: keyed by pid alone, so a reused pid of another .NET process is not asked; key by
// start time if that shows up.
var dotnetAsked sync.Map

// askDotnet asks a .NET process without a perf map to start one, once, through the diagnostics
// socket in its own /tmp. A process with diagnostics off (DOTNET_EnableDiagnostics=0) has none.
func (r *procResolver) askDotnet(pid uint32, ms []Mapping) {
	if _, done := dotnetAsked.LoadOrStore(pid, true); done {
		return
	}
	coreclr := false
	for _, m := range ms {
		coreclr = coreclr || path.Base(m.Path) == "libcoreclr.so"
	}
	if !coreclr {
		return
	}
	dir := filepath.Join(r.proc, strconv.Itoa(int(pid)))
	ns := pid
	if f, err := os.Open(filepath.Join(dir, "status")); err == nil {
		if n, ok := NSPid(f); ok {
			ns = n
		}
		f.Close()
	}
	socks, _ := filepath.Glob(filepath.Join(dir, "root", "tmp", fmt.Sprintf("dotnet-diagnostic-%d-*-socket", ns)))
	if len(socks) == 0 {
		slog.Info("ebpf_profiler: .NET process has no diagnostics socket, JIT frames stay unnamed", "pid", pid)
		return
	}
	err := func() error {
		c, err := net.DialTimeout("unix", socks[0], time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		return enableDotnetPerfMap(c)
	}()
	if err != nil {
		slog.Info("ebpf_profiler: .NET perf map not enabled", "pid", pid, "err", err)
		return
	}
	slog.Info("ebpf_profiler: .NET perf map enabled", "pid", pid)
}

func (r *procResolver) Meta(pid uint32) Meta {
	if m, ok := r.metas[pid]; ok {
		return m
	}
	dir := filepath.Join(r.proc, strconv.Itoa(int(pid)))
	l := map[string]string{"host": r.host}
	exe, _ := os.Readlink(filepath.Join(dir, "exe"))
	if exe == "" {
		b, _ := os.ReadFile(filepath.Join(dir, "comm"))
		exe = strings.TrimSpace(string(b))
	}
	l["process.executable"] = exe
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		l["process.command_line"] = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	service := filepath.Base(exe)
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		if id := containerRe.FindString(string(cg)); id != "" {
			l["container"] = id[:12]
			service = "container/" + id[:12]
		}
		if p := podRe.FindStringSubmatch(string(cg)); p != nil {
			l["k8s.pod"] = strings.ReplaceAll(p[1], "_", "-")
		}
	}
	m := Meta{Service: service, Labels: l}
	r.metas[pid] = m
	return m
}
