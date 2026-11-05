package runtimesec

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

// Event is one decoded runtime-security event from the eBPF ring buffer. The kernel fills the
// probe fields (Kind..Path); the loader fills InContainer and Service after resolving the pid's
// cgroup (see loader_linux.go). Match reads this; it is pure Go so the decode + policy logic is
// unit-tested without a kernel.
type Event struct {
	Kind   string // exec | file | network (from the probe that produced it)
	PID    uint32
	UID    uint32
	Cgroup uint64
	Op     string // file: read|write ; network: egress|ingress ; "" for exec
	DPort  uint16 // network: destination port in host order ; 0 otherwise
	Comm   string // process name (TASK_COMM_LEN, null-trimmed)
	Path   string // file path or exec'd filename (null-trimmed)

	InContainer bool   // pid resolved to a container cgroup
	Service     string // container service name (namespace/pod, workload, or container/<id12>); process name off-cluster
}

// EventSize is sizeof(struct rt_event) in bpf/runtimesec.bpf.c. Any change there must change this
// and the offsets in DecodeEvent together, or events decode as garbage.
const EventSize = 312

const (
	kindExec    = 0
	kindFile    = 1
	kindNetwork = 2
	opWrite     = 1 // file op / network direction: 1 = write / egress, 0 = read / ingress
)

// cstr returns the null-terminated prefix of a fixed C char array as a Go string.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// DecodeEvent decodes one struct rt_event. It returns false when the record is too short. It fills
// only the kernel-sourced fields; the loader sets InContainer and Service.
func DecodeEvent(b []byte) (Event, bool) {
	if len(b) < EventSize {
		return Event{}, false
	}
	le := binary.LittleEndian
	kind := le.Uint32(b[24:])
	op := le.Uint32(b[28:])
	ev := Event{
		Cgroup: le.Uint64(b[8:]),
		PID:    le.Uint32(b[16:]),
		UID:    le.Uint32(b[20:]),
		DPort:  uint16(le.Uint32(b[32:])),
		Comm:   cstr(b[40:56]),
		Path:   cstr(b[56:312]),
	}
	switch kind {
	case kindExec:
		ev.Kind = "exec"
	case kindFile:
		ev.Kind = "file"
		if op == opWrite {
			ev.Op = "write"
		} else {
			ev.Op = "read"
		}
	case kindNetwork:
		ev.Kind = "network"
		if op == opWrite {
			ev.Op = "egress"
		} else {
			ev.Op = "ingress"
		}
	default:
		return Event{}, false
	}
	return ev, true
}

// Hit is a policy rule an event tripped, with the detail attributes to carry on the signal.
type Hit struct {
	Rule   Rule
	Detail map[string]string
}

// Match returns every enabled rule the event trips. The kind-specific matchers mirror the DefaultPolicy
// shapes (exec: comm set + in_container; file: op + path prefixes; network: direction + deny_ports).
func (p Policy) Match(ev Event) []Hit {
	var hits []Hit
	for _, r := range p.Rules {
		if r.Kind != ev.Kind {
			continue
		}
		var ok bool
		switch ev.Kind {
		case "exec":
			ok = matchExec(r.Match, ev)
		case "file":
			ok = matchFile(r.Match, ev)
		case "network":
			ok = matchNetwork(r.Match, ev)
		}
		if ok {
			hits = append(hits, Hit{Rule: r, Detail: detail(ev)})
		}
	}
	return hits
}

func matchExec(m map[string]any, ev Event) bool {
	if b, ok := m["in_container"].(bool); ok && b && !ev.InContainer {
		return false
	}
	comms := strSet(m["comm"])
	if len(comms) == 0 { // a rule with no comm filter matches any exec
		return true
	}
	return comms[ev.Comm]
}

func matchFile(m map[string]any, ev Event) bool {
	if op, ok := m["op"].(string); ok && op != ev.Op {
		return false
	}
	return hasPrefix(strList(m["paths"]), ev.Path)
}

func matchNetwork(m map[string]any, ev Event) bool {
	if dir, ok := m["direction"].(string); ok && dir != ev.Op {
		return false
	}
	return intSet(m["deny_ports"])[int(ev.DPort)]
}

func detail(ev Event) map[string]string {
	d := map[string]string{"comm": ev.Comm, "pid": strconv.FormatUint(uint64(ev.PID), 10)}
	if ev.Path != "" {
		d["path"] = ev.Path
	}
	if ev.Op != "" {
		d["op"] = ev.Op
	}
	if ev.DPort != 0 {
		d["dport"] = strconv.FormatUint(uint64(ev.DPort), 10)
	}
	return d
}

// strSet / strList / intSet read a JSON-decoded matcher value ([]any of strings/numbers, as
// encoding/json produces) into Go. A string slice or an []any both work, so a policy built in Go or
// unmarshalled from JSON matches the same way.
func strSet(v any) map[string]bool {
	s := map[string]bool{}
	for _, x := range strList(v) {
		s[x] = true
	}
	return s
}

func strList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func intSet(v any) map[int]bool {
	s := map[int]bool{}
	switch t := v.(type) {
	case []int:
		for _, x := range t {
			s[x] = true
		}
	case []any:
		for _, x := range t {
			if f, ok := x.(float64); ok { // JSON numbers decode as float64
				s[int(f)] = true
			}
		}
	}
	return s
}

// hasPrefix reports whether path is, or sits under, one of the rule's paths. "/bin" covers
// "/bin/sh"; "/etc/passwd" matches only that exact file; a trailing "/" matches the subtree.
func hasPrefix(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}
