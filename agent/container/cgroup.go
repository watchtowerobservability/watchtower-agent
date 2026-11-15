package container

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// DefaultCgroupRoot is where cgroup v2 is mounted.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// scopeRE matches the cgroup leaf of a container: docker, podman (libpod), containerd (cri) and
// cri-o all name it <runtime>-<64 hex>.scope.
// Also matched: the bare /docker/<id> layout (cgroupfs driver, no systemd).
var scopeRE = regexp.MustCompile(`^(?:(?:docker|libpod|cri-containerd|crio)-)?([0-9a-f]{64})(?:\.scope)?$`)

// CG is one container's cgroup reading.
type CG struct {
	ID         string
	CPUUsageNS uint64
	MemBytes   uint64
	// MemLimit is memory.max (0: unlimited); the rest are plain readings (Has* false when the file is absent).
	MemLimit, MemAnon, MemFile uint64
	IORead, IOWrite            uint64
	Pids                       uint64
	HasPids, HasIO             bool
}

// ParseCPUStat returns usage_usec of a cgroup v2 cpu.stat file, in nanoseconds.
func ParseCPUStat(s string) (uint64, bool) {
	for _, l := range strings.Split(s, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "usage_usec" {
			n, err := strconv.ParseUint(f[1], 10, 64)
			return n * 1000, err == nil
		}
	}
	return 0, false
}

// ParseMemoryStat returns the value of key in a cgroup v2 flat-keyed file such as memory.stat.
func ParseMemoryStat(s, key string) uint64 {
	for _, l := range strings.Split(s, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == key {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n
		}
	}
	return 0
}

// ParseIOStat sums rbytes and wbytes over the devices of a cgroup v2 io.stat file.
func ParseIOStat(s string) (read, write uint64) {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		for _, kv := range f[1:] {
			k, v, _ := strings.Cut(kv, "=")
			n, _ := strconv.ParseUint(v, 10, 64)
			switch k {
			case "rbytes":
				read += n
			case "wbytes":
				write += n
			}
		}
	}
	return
}

// containerNames reads WT_AGENT_CONTAINER_NAMES: one "<id or id prefix> <name>" per line, `#` comments.
func containerNames() map[string]string {
	f := os.Getenv("WT_AGENT_CONTAINER_NAMES")
	if f == "" {
		return nil
	}
	m := map[string]string{}
	for _, l := range strings.Split(readFile(f), "\n") {
		if a := strings.Fields(l); len(a) == 2 && !strings.HasPrefix(a[0], "#") {
			m[a[0]] = a[1]
		}
	}
	return m
}

func nameFor(names map[string]string, id string) string {
	for k, v := range names {
		if strings.HasPrefix(id, k) {
			return v
		}
	}
	return id[:12]
}

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// ScanCgroups walks root (at most 8 levels, at most maxContainers hits) for container scopes
// and reads their CPU time and working-set memory (memory.current minus inactive_file).
func ScanCgroups(root string) []CG {
	var out []CG
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || !e.IsDir() {
			return nil
		}
		if strings.Count(p, string(filepath.Separator))-rootDepth > 8 {
			return fs.SkipDir
		}
		m := scopeRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil
		}
		cpu, ok := ParseCPUStat(readFile(filepath.Join(p, "cpu.stat")))
		if !ok {
			return fs.SkipDir
		}
		mem, _ := strconv.ParseUint(strings.TrimSpace(readFile(filepath.Join(p, "memory.current"))), 10, 64)
		if ina := ParseMemoryStat(readFile(filepath.Join(p, "memory.stat")), "inactive_file"); ina < mem {
			mem -= ina
		}
		cg := CG{ID: m[1], CPUUsageNS: cpu, MemBytes: mem}
		ms := readFile(filepath.Join(p, "memory.stat"))
		cg.MemAnon, cg.MemFile = ParseMemoryStat(ms, "anon"), ParseMemoryStat(ms, "file")
		cg.MemLimit, _ = strconv.ParseUint(strings.TrimSpace(readFile(filepath.Join(p, "memory.max"))), 10, 64) // "max" parses to 0
		if v := strings.TrimSpace(readFile(filepath.Join(p, "pids.current"))); v != "" {
			cg.Pids, _ = strconv.ParseUint(v, 10, 64)
			cg.HasPids = true
		}
		if io := readFile(filepath.Join(p, "io.stat")); io != "" {
			cg.IORead, cg.IOWrite = ParseIOStat(io)
			cg.HasIO = true
		}
		out = append(out, cg)
		if len(out) >= maxContainers {
			return fs.SkipAll
		}
		return fs.SkipDir
	})
	return out
}

// CollectCgroups reports containers the Engine API did not list (known holds ids already
// reported) and adds the ids it reports to known. Without a name or image, the name is the short id.
func (p *Poller) CollectCgroups(root string, known map[string]bool, out sink.Sink) {
	if p.prev == nil {
		p.prev = map[string]Stats{}
	}
	now := time.Now()
	names := containerNames()
	for _, c := range ScanCgroups(root) {
		if known[c.ID] {
			continue
		}
		known[c.ID] = true
		// a bare cgroup scan carries no labels/env: service.name falls back to the short id so the
		// container is not reported under the agent's own identity (W62).
		info := Info{ID: c.ID, Name: nameFor(names, c.ID)}
		id := ResolveIdentity(nil, nil, p.Services, info.Name)
		p.emit(out, info, Stats{CPUTotalNS: c.CPUUsageNS, MemUsage: c.MemBytes, At: now}, id)
		attrs := withRes(map[string]string{"container.id": c.ID, "container.name": info.Name})
		for k, v := range sink.Res(id.Resource()) {
			attrs[k] = v
		}
		gaugeProm(out, "container.memory.anon", "By", float64(c.MemAnon), attrs, now)
		gaugeProm(out, "container.memory.file", "By", float64(c.MemFile), attrs, now)
		if c.MemLimit > 0 {
			gaugeProm(out, "container.memory.limit", "By", float64(c.MemLimit), attrs, now)
		}
		if c.HasPids {
			gaugeProm(out, "container.pids.count", "{pid}", float64(c.Pids), attrs, now)
		}
		if c.HasIO {
			out.Sum("container.blockio.read", "By", float64(c.IORead), attrs, now)
			out.Sum("container.blockio.write", "By", float64(c.IOWrite), attrs, now)
		}
	}
}
