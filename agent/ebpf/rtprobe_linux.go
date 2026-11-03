//go:build linux

package ebpf

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const rtMaxRodata = 64 << 20 // PHP's version scan reads this much of a binary at most

type pidMem int

// ReadAt never touches the target: process_vm_readv does not stop it, cannot write to it here, and
// fails on an unmapped address.
func (p pidMem) ReadAt(addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	local := []unix.Iovec{{Base: (*byte)(unsafe.Pointer(&b[0])), Len: uint64(len(b))}}
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(b)}}
	n, err := unix.ProcessVMReadv(int(p), local, remote, 0)
	if err != nil {
		return err
	}
	if n != len(b) {
		return errors.New("short read")
	}
	return nil
}

// rtRuntime is one runtime this module can read.
type rtRuntime struct {
	name  string // as in runtime_stacks; "python" for python_stacks
	kind  Kind
	lib   *regexp.Regexp // the mapped file holding its symbols
	wants func(string) bool
	open  func(mem memReader, img *rtImage) (stackWalker, error)
}

var rtRuntimes = []rtRuntime{
	{"python", PythonWall, regexp.MustCompile(`^(lib)?python3`), func(s string) bool { return s == "_PyRuntime" || s == "Py_Version" }, openPython},
	{"ruby", RubyWall, regexp.MustCompile(`^(ruby|libruby)`), func(s string) bool { return s == "ruby_current_vm_ptr" || s == "ruby_version" }, openRuby},
	{"php", PHPWall, regexp.MustCompile(`^(php|libphp|mod_php)`), func(s string) bool { return s == "executor_globals" || s == "executor_globals_offset" }, openPHP},
	{"node", NodeCPU, regexp.MustCompile(`^(node|libnode)`), func(s string) bool { return strings.HasPrefix(s, "v8dbg_") }, openNode},
	{"jvm", JVMWall, regexp.MustCompile(`^libjvm\.so`), func(s string) bool { return strings.HasPrefix(s, "gHotSpotVM") }, openJVM},
}

// rtImage is a runtime's mapped ELF file, with its wanted symbols at their addresses in the target.
type rtImage struct {
	file *elf.File
	syms map[string]uint64
	bias uint64
	// legacyPy is the python_legacy opt-in.
	legacyPy bool
}

// detectRuntime finds the first enabled runtime whose file pid maps. It returns a nil image for
// a process that runs none of them.
func detectRuntime(pid uint32, enabled map[string]bool) (*rtRuntime, *rtImage, error) {
	dir := filepath.Join("/proc", strconv.Itoa(int(pid)))
	mf, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return nil, nil, err
	}
	ms := ParseMaps(mf)
	mf.Close()
	for i := range rtRuntimes {
		rt := &rtRuntimes[i]
		if !enabled[rt.name] {
			continue
		}
		for _, m := range ms {
			if !rt.lib.MatchString(path.Base(m.Path)) {
				continue
			}
			f, err := elf.Open(filepath.Join(dir, "root", m.Path))
			if err != nil {
				continue
			}
			img, ok := loadImage(f, m.Start, m.Offset, rt.wants)
			if ok {
				return rt, img, nil
			}
			f.Close()
		}
	}
	return nil, nil, nil
}

func loadImage(f *elf.File, start, offset uint64, wants func(string) bool) (*rtImage, bool) {
	shift, ok := uint64(0), false
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Off <= offset && offset < p.Off+p.Filesz {
			shift, ok = p.Vaddr-p.Off, true
			break
		}
	}
	if !ok {
		return nil, false
	}
	bias := start - offset - shift
	img := &rtImage{file: f, syms: map[string]uint64{}, bias: bias}
	syms, _ := f.DynamicSymbols()
	if more, err := f.Symbols(); err == nil {
		syms = append(syms, more...)
	}
	for _, s := range syms {
		if s.Value != 0 && wants(s.Name) {
			img.syms[s.Name] = s.Value + bias
		}
	}
	return img, len(img.syms) > 0 || f.Section(".PyRuntime") != nil
}

func openPython(mem memReader, img *rtImage) (stackWalker, error) {
	rt := img.syms["_PyRuntime"]
	if s := img.file.Section(".PyRuntime"); s != nil {
		rt = s.Addr + img.bias
	}
	if rt == 0 {
		return nil, errors.New("no _PyRuntime symbol")
	}
	var ver uint64
	if a, ok := img.syms["Py_Version"]; ok {
		var err error
		if ver, err = (rmem{mem}).u64(a); err != nil {
			return nil, err
		}
	}
	return newPyWalkerFor(mem, rt, ver, img.legacyPy)
}

func openRuby(mem memReader, img *rtImage) (stackWalker, error) {
	vm, ok1 := img.syms["ruby_current_vm_ptr"]
	va, ok2 := img.syms["ruby_version"]
	if !ok1 || !ok2 {
		return nil, errors.New("no ruby_current_vm_ptr: it is a local symbol, so a stripped libruby is refused (install its debug symbols or build unstripped)")
	}
	ver, err := rmem{mem}.cstr(va, 32)
	if err != nil {
		return nil, err
	}
	return newRubyWalker(mem, vm, ver)
}

func openPHP(mem memReader, img *rtImage) (stackWalker, error) {
	eg, ok := img.syms["executor_globals"]
	if !ok {
		return nil, errors.New("no executor_globals: thread-safe (ZTS) PHP builds are refused, their globals are per thread")
	}
	s := img.file.Section(".rodata")
	if s == nil || s.Size > rtMaxRodata {
		return nil, errors.New("PHP binary has no readable .rodata to find its version in")
	}
	data, err := s.Data()
	if err != nil {
		return nil, err
	}
	return newPHPWalker(mem, eg, phpVersion(data))
}

func openNode(mem memReader, img *rtImage) (stackWalker, error) {
	m := rmem{mem}
	get := func(name string) (int64, bool) {
		for s, a := range img.syms {
			t := strings.TrimPrefix(s, "v8dbg_")
			if t == name || (strings.HasSuffix(name, "__") && strings.HasPrefix(t, name)) {
				v, err := m.u32(a)
				return int64(int32(v)), err == nil
			}
		}
		return 0, false
	}
	return newNodeWalker(m, get, img.syms["v8dbg_TaggedSize"])
}

func openJVM(mem memReader, img *rtImage) (stackWalker, error) {
	return newJVMWalker(mem, jvmSyms(img.syms))
}

// attachRuntime is the whole attach: detect, pick the table, self-check. A nil walker with a nil
// error means pid runs no enabled runtime.
func attachRuntime(pid uint32, mem memReader, enabled map[string]bool) (stackWalker, *rtRuntime, error) {
	rt, img, err := detectRuntime(pid, enabled)
	if err != nil || rt == nil {
		return nil, nil, err
	}
	defer img.file.Close()
	img.legacyPy = enabled["python_legacy"]
	w, err := rt.open(mem, img)
	if err != nil {
		return nil, rt, fmt.Errorf("%s: %w", rt.name, err)
	}
	if err := w.selfCheck(); err != nil {
		return nil, rt, fmt.Errorf("%s: %w", rt.name, err)
	}
	return w, rt, nil
}
