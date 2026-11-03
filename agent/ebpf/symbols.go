package ebpf

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"
	"strconv"
	"strings"
)

// The parsers here are plain text and have no Linux dependency, so they are tested everywhere.
// The Linux-only code that feeds them from /proc is in stacks_linux.go and symbols_linux.go.

type sym struct {
	addr, size uint64
	name       string
}

// Kallsyms resolves kernel addresses from /proc/kallsyms content.
type Kallsyms struct{ syms []sym }

// ParseKallsyms reads `addr type name [module]` lines, keeping text symbols. Unprivileged
// readers see all-zero addresses; those lines are skipped so Lookup finds nothing.
func ParseKallsyms(r io.Reader) *Kallsyms {
	k := &Kallsyms{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !strings.ContainsAny(f[1], "TtWw") {
			continue
		}
		a, err := strconv.ParseUint(f[0], 16, 64)
		if err != nil || a == 0 {
			continue
		}
		k.syms = append(k.syms, sym{addr: a, name: f[2]})
	}
	sort.Slice(k.syms, func(i, j int) bool { return k.syms[i].addr < k.syms[j].addr })
	return k
}

// Lookup returns the symbol at or below addr, or "" when addr is below the table.
func (k *Kallsyms) Lookup(addr uint64) string {
	i := sort.Search(len(k.syms), func(i int) bool { return k.syms[i].addr > addr })
	if i == 0 {
		return ""
	}
	return k.syms[i-1].name
}

// PerfMap resolves JIT addresses from a /tmp/perf-<pid>.map file (`START SIZE name`, hex).
type PerfMap struct{ syms []sym }

// ParsePerfMap reads a perf map.
func ParsePerfMap(r io.Reader) *PerfMap {
	p := &PerfMap{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), " ", 3)
		if len(f) < 3 {
			continue
		}
		a, e1 := strconv.ParseUint(f[0], 16, 64)
		n, e2 := strconv.ParseUint(f[1], 16, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		p.syms = append(p.syms, sym{addr: a, size: n, name: f[2]})
	}
	sort.Slice(p.syms, func(i, j int) bool { return p.syms[i].addr < p.syms[j].addr })
	return p
}

// NSPid reads the innermost namespace pid from /proc/<pid>/status (`NSpid:` lists the pid in
// each nested pid namespace, outermost first). A process in a container writes its perf map
// under that pid.
func NSPid(r io.Reader) (uint32, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "NSpid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0, false
		}
		n, err := strconv.ParseUint(f[len(f)-1], 10, 32)
		return uint32(n), err == nil
	}
	return 0, false
}

// Lookup returns the symbol covering addr.
func (p *PerfMap) Lookup(addr uint64) (string, bool) {
	i := sort.Search(len(p.syms), func(i int) bool { return p.syms[i].addr > addr })
	if i == 0 {
		return "", false
	}
	s := p.syms[i-1]
	if addr >= s.addr+s.size {
		return "", false
	}
	return s.name, true
}

// Mapping is one line of /proc/<pid>/maps.
type Mapping struct {
	Start, End, Offset uint64
	Path               string
}

// ParseMaps reads /proc/<pid>/maps, keeping executable mappings, sorted by start.
func ParseMaps(r io.Reader) []Mapping {
	var out []Mapping
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || len(f[1]) < 3 || f[1][2] != 'x' {
			continue
		}
		lo, hi, ok := strings.Cut(f[0], "-")
		if !ok {
			continue
		}
		s, e1 := strconv.ParseUint(lo, 16, 64)
		e, e2 := strconv.ParseUint(hi, 16, 64)
		off, e3 := strconv.ParseUint(f[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		p := ""
		if len(f) > 5 {
			p = strings.Join(f[5:], " ")
		}
		out = append(out, Mapping{Start: s, End: e, Offset: off, Path: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// FindMapping returns the mapping that contains addr.
func FindMapping(ms []Mapping, addr uint64) (Mapping, bool) {
	i := sort.Search(len(ms), func(i int) bool { return ms[i].End > addr })
	if i < len(ms) && ms[i].Start <= addr {
		return ms[i], true
	}
	return Mapping{}, false
}

// BuildID returns the hex GNU build id of an ELF file, or "" when it has none.
func BuildID(path string) string {
	f, err := elf.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return ""
	}
	b, err := s.Data()
	if err != nil || len(b) < 12 {
		return ""
	}
	namesz, descsz := binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint32(b[4:])
	start := 12 + (uint64(namesz)+3)&^3
	if start+uint64(descsz) > uint64(len(b)) {
		return ""
	}
	return hex.EncodeToString(b[start : start+uint64(descsz)])
}
