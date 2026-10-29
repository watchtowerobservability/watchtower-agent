//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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
}

func newProcResolver(host string) *procResolver {
	r := &procResolver{proc: "/proc", host: host, maps: map[uint32][]Mapping{}, perf: map[uint32]*PerfMap{},
		buildID: map[string]string{}, metas: map[uint32]Meta{}, kernel: &Kallsyms{}}
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
	if f, err := os.Open(fmt.Sprintf("/tmp/perf-%d.map", pid)); err == nil {
		p = ParsePerfMap(f)
		f.Close()
	}
	r.perf[pid] = p
	return p
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
