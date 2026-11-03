package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"
)

// CPython 3.13+ describes its own layout: _PyRuntime starts with _Py_DebugOffsets, a table of
// byte offsets behind the cookie "xdebugpy". pyWords says where each offset we use sits in that
// table, per minor version (word indices checked with offsetof against each version's headers).
// 3.11 and 3.12 have no such table: pyold.go carries theirs.
type pyWords struct {
	interpHead, interpNext, threadsHead, threadNext, curFrame, nativeTid uint64
	framePrev, frameExec, frameOwner                                     uint64
	codeFilename, codeQualname, obType, tpName                           uint64
	uniState, uniLen, uniASCII, tableWords                               uint64
}

var pyTables = map[uint64]pyWords{
	13: {5, 8, 9, 21, 23, 25, 29, 30, 33, 35, 37, 45, 47, 68, 69, 70, 73},
	14: {5, 8, 9, 24, 26, 28, 32, 33, 36, 40, 42, 51, 53, 78, 79, 80, 95},
	15: {5, 8, 9, 24, 26, 31, 40, 41, 44, 48, 50, 59, 61, 90, 91, 92, 111},
}

const (
	pyMaxInterps   = 8
	pyMaxThreads   = 512
	pyMaxFrames    = 128
	pyMaxString    = 512
	pyOwnedByFrame = 3 // owners below this are Python frames (thread, generator, frame object)
	pyCompactASCII = 0x60
)

// memReader reads another process's memory; a bad address is an error, never a fault.
type memReader interface {
	ReadAt(addr uint64, b []byte) error
}

// PyStack is one Python thread's stack, leaf first.
type PyStack struct {
	Thread uint64
	Frames []string
}

// pyWalker reads Python stacks of one process. The target keeps running, so a value can be stale:
// every loop is bounded, and a read that fails or a code object that fails its type check ends
// that stack only.
type pyWalker struct {
	mem     memReader
	runtime uint64
	off     map[string]uint64
	names   map[uint64]string // code object -> frame name
}

func newPyWalker(mem memReader, runtime uint64) (*pyWalker, error) {
	head := make([]byte, 24)
	if err := mem.ReadAt(runtime, head); err != nil {
		return nil, err
	}
	if string(head[:8]) != "xdebugpy" {
		return nil, errors.New("no _Py_DebugOffsets cookie")
	}
	ver := binary.LittleEndian.Uint64(head[8:])
	if ver>>24 != 3 {
		return nil, fmt.Errorf("python version %#x is not 3.x", ver)
	}
	t, ok := pyTables[ver>>16&0xff]
	if !ok {
		return nil, fmt.Errorf("python 3.%d has no offset table here", ver>>16&0xff)
	}
	if binary.LittleEndian.Uint64(head[16:]) != 0 {
		return nil, errFreeThreaded
	}
	raw := make([]byte, 8*t.tableWords)
	if err := mem.ReadAt(runtime, raw); err != nil {
		return nil, err
	}
	w := func(i uint64) uint64 { return binary.LittleEndian.Uint64(raw[8*i:]) }
	return &pyWalker{mem: mem, runtime: runtime, names: map[uint64]string{}, off: map[string]uint64{
		"interpHead": w(t.interpHead), "interpNext": w(t.interpNext), "threadsHead": w(t.threadsHead),
		"threadNext": w(t.threadNext), "curFrame": w(t.curFrame), "nativeTid": w(t.nativeTid),
		"framePrev": w(t.framePrev), "frameExec": w(t.frameExec), "frameOwner": w(t.frameOwner),
		"codeFilename": w(t.codeFilename), "codeQualname": w(t.codeQualname), "obType": w(t.obType),
		"tpName": w(t.tpName), "uniState": w(t.uniState), "uniLen": w(t.uniLen), "uniASCII": w(t.uniASCII),
	}}, nil
}

func (p *pyWalker) ptr(addr uint64) (uint64, error) {
	var b [8]byte
	if err := p.mem.ReadAt(addr, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func (p *pyWalker) str(obj uint64) (string, error) {
	var b [8]byte
	if err := p.mem.ReadAt(obj+p.off["uniState"], b[:4]); err != nil {
		return "", err
	}
	if binary.LittleEndian.Uint32(b[:4])&pyCompactASCII != pyCompactASCII {
		return "?", nil // non-ASCII names need the kind-specific layout
	}
	n, err := p.ptr(obj + p.off["uniLen"])
	if err != nil {
		return "", err
	}
	if n > pyMaxString {
		return "", errors.New("implausible string length")
	}
	s := make([]byte, n)
	if err := p.mem.ReadAt(obj+p.off["uniASCII"], s); err != nil {
		return "", err
	}
	return string(s), nil
}

func (p *pyWalker) isCode(obj uint64) bool {
	typ, err := p.ptr(obj + p.off["obType"])
	if err != nil {
		return false
	}
	name, err := p.ptr(typ + p.off["tpName"])
	if err != nil {
		return false
	}
	var b [5]byte
	return p.mem.ReadAt(name, b[:]) == nil && string(b[:]) == "code\x00"
}

// frameName is `qualname (file.py)`, cached per code object for the walker's life.
func (p *pyWalker) frameName(code uint64) (string, bool) {
	if n, ok := p.names[code]; ok {
		return n, true
	}
	if !p.isCode(code) {
		return "", false
	}
	qual, err := p.ptr(code + p.off["codeQualname"])
	if err != nil {
		return "", false
	}
	file, err := p.ptr(code + p.off["codeFilename"])
	if err != nil {
		return "", false
	}
	q, e1 := p.str(qual)
	f, e2 := p.str(file)
	if e1 != nil || e2 != nil {
		return "", false
	}
	n := strings.ReplaceAll(q+" ("+path.Base(f)+")", ";", ":")
	p.names[code] = n
	return n, true
}

func (p *pyWalker) thread(ts uint64) PyStack {
	st := PyStack{}
	st.Thread, _ = p.ptr(ts + p.off["nativeTid"])
	frame, err := p.currentFrame(ts)
	for i := 0; err == nil && frame != 0 && i < pyMaxFrames; i++ {
		var owner [1]byte
		if p.mem.ReadAt(frame+p.off["frameOwner"], owner[:]) != nil {
			break
		}
		if owner[0] < pyOwnedByFrame {
			exec, e := p.ptr(frame + p.off["frameExec"])
			if e != nil {
				break
			}
			// 3.14+ keeps a tagged stack reference here: the low bits are not address.
			if n, ok := p.frameName(exec &^ 3); ok {
				st.Frames = append(st.Frames, n)
			}
		}
		frame, err = p.ptr(frame + p.off["framePrev"])
	}
	return st
}

// Stacks reads every thread of every interpreter.
func (p *pyWalker) Stacks() ([]PyStack, error) {
	var out []PyStack
	interp, err := p.ptr(p.runtime + p.off["interpHead"])
	if err != nil {
		return nil, err
	}
	for i := 0; interp != 0 && i < pyMaxInterps; i++ {
		ts, err := p.ptr(interp + p.off["threadsHead"])
		for t := 0; err == nil && ts != 0 && t < pyMaxThreads; t++ {
			if st := p.thread(ts); len(st.Frames) > 0 {
				out = append(out, st)
			}
			ts, err = p.ptr(ts + p.off["threadNext"])
		}
		if interp, err = p.ptr(interp + p.off["interpNext"]); err != nil {
			return out, err
		}
	}
	return out, nil
}
