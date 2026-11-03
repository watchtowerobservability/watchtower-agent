package trace

// Process selection (CFT-E16): which processes ebpf_trace makes spans for. `include` (when set)
// and `exclude` hold selectors matched on the executable path (glob), process name, listening
// port or a cgroup substring (a pod UID or container id). Processes that already send OTLP
// themselves (OTEL_* exporter settings in their environment, or the OTel Java agent on the
// command line) are skipped by default, so a service is not traced twice.

import (
	"bytes"
	"path"
	"strings"
	"sync"
	"time"
)

// Selector matches a process when every set field matches.
type Selector struct {
	ExePath string `json:"exe_path"` // glob on the path or a trailing part: /usr/bin/node, */java
	Name    string `json:"name"`     // /proc/<pid>/comm
	Port    int    `json:"port"`     // a TCP port the process listens on
	Cgroup  string `json:"cgroup"`   // substring of /proc/<pid>/cgroup
}

// ProcInfo is what selection reads about a process.
type ProcInfo struct {
	Exe, Name, Cgroup string
	Ports             []int
	Environ, Cmdline  []byte // NUL-separated
}

func (s Selector) match(p ProcInfo) bool {
	if s.ExePath != "" && !globSuffix(s.ExePath, p.Exe) {
		return false
	}
	if s.Name != "" && s.Name != p.Name {
		return false
	}
	if s.Cgroup != "" && !strings.Contains(p.Cgroup, s.Cgroup) {
		return false
	}
	if s.Port > 0 {
		found := false
		for _, x := range p.Ports {
			found = found || x == s.Port
		}
		if !found {
			return false
		}
	}
	return s != Selector{}
}

// globSuffix matches pattern against the path or any of its trailing segments, so `*/java`
// matches /usr/lib/jvm/bin/java (a `*` never crosses a slash).
func globSuffix(pattern, p string) bool {
	for {
		if ok, _ := path.Match(pattern, p); ok {
			return true
		}
		i := strings.IndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[i+1:]
	}
}

// OTelInstrumented reports whether the process exports OTLP on its own.
func OTelInstrumented(p ProcInfo) bool {
	for _, kv := range bytes.Split(p.Environ, []byte{0}) {
		if bytes.HasPrefix(kv, []byte("OTEL_EXPORTER_OTLP_")) || bytes.HasPrefix(kv, []byte("OTEL_TRACES_EXPORTER=otlp")) {
			return true
		}
	}
	return bytes.Contains(p.Cmdline, []byte("opentelemetry-javaagent"))
}

// Selection decides per pid, caching each answer for a minute (pids are reused).
type Selection struct {
	Include, Exclude []Selector
	SkipInstrumented bool
	Read             func(pid uint32) (ProcInfo, bool)

	mu      sync.Mutex
	cache   map[uint32]selEntry
	skipped uint64
}

type selEntry struct {
	keep bool
	at   time.Time
}

// Active reports whether any rule can drop a process.
func (s *Selection) Active() bool {
	return s != nil && (len(s.Include) > 0 || len(s.Exclude) > 0 || s.SkipInstrumented)
}

// Keep reports whether events of pid become spans.
func (s *Selection) Keep(pid uint32, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.cache[pid]; ok && now.Sub(e.at) < time.Minute {
		return e.keep
	}
	keep := true
	if p, ok := s.Read(pid); ok {
		keep = s.decide(p)
	}
	if s.cache == nil || len(s.cache) > 8192 {
		s.cache = map[uint32]selEntry{}
	}
	s.cache[pid] = selEntry{keep, now}
	if !keep {
		s.skipped++
	}
	return keep
}

func (s *Selection) decide(p ProcInfo) bool {
	for _, x := range s.Exclude {
		if x.match(p) {
			return false
		}
	}
	if len(s.Include) > 0 {
		in := false
		for _, x := range s.Include {
			in = in || x.match(p)
		}
		if !in {
			return false
		}
	}
	return !(s.SkipInstrumented && OTelInstrumented(p))
}

// Skipped is how many processes were left out (counted once per cache period).
func (s *Selection) Skipped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.skipped
}
