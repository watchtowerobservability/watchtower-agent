package ebpf

import (
	"errors"
	"fmt"
)

// errFreeThreaded: those builds change the object header, the thread list and the frame refs, and
// a reader without per-object locks would race them.
var errFreeThreaded = errors.New("free-threaded CPython is refused: its object and frame layout differ and it has no GIL to keep them coherent")

// pyOldTables are the offsets of the CPython versions that do not publish _Py_DebugOffsets, from
// each branch's Include/ headers (checked with offsetof on an LP64 build; 3.11 and 3.12 are the
// branches under upstream security support on 2026-10-31). Layouts of a Linux build are not proven
// by that: selfCheck is what admits a process.
var pyOldTables = map[uint64]map[string]uint64{
	11: {
		"initialized": 16, "interpHead": 40, "interpNext": 0, "threadsHead": 16, "threadNext": 8, "tsInterp": 16,
		"cframe": 56, "cframeCur": 8, "nativeTid": 160, "framePrev": 48, "frameExec": 32, "frameOwner": 69,
		"codeFilename": 112, "codeQualname": 128, "obType": 8, "tpName": 24, "uniState": 32, "uniLen": 16, "uniASCII": 48,
	},
	12: {
		"initialized": 16, "interpHead": 40, "interpNext": 0, "threadsHead": 72, "threadNext": 8, "tsInterp": 16,
		"cframe": 56, "cframeCur": 0, "nativeTid": 144, "framePrev": 8, "frameExec": 0, "frameOwner": 70,
		"codeFilename": 112, "codeQualname": 128, "obType": 8, "tpName": 24, "uniState": 32, "uniLen": 16, "uniASCII": 40,
	},
}

// newPyWalkerFor picks the table for a process: version is the target's Py_Version (0 when the
// symbol is missing, as before 3.11). 3.13+ describes itself; a table version needs legacy, the
// python_legacy opt-in.
func newPyWalkerFor(mem memReader, runtime, version uint64, legacy bool) (*pyWalker, error) {
	var cookie [8]byte
	if err := mem.ReadAt(runtime, cookie[:]); err != nil {
		return nil, err
	}
	if string(cookie[:]) == "xdebugpy" {
		return newPyWalker(mem, runtime)
	}
	if version == 0 {
		return nil, errors.New("no Py_Version symbol: CPython before 3.11 is past upstream support")
	}
	minor := version >> 16 & 0xff
	t, ok := pyOldTables[minor]
	if !ok || version>>24 != 3 {
		return nil, fmt.Errorf("CPython %#x has no offset table", version)
	}
	if !legacy {
		return nil, fmt.Errorf("CPython 3.%d is not read by default: add python_legacy to runtime_stacks", minor)
	}
	return &pyWalker{mem: mem, runtime: runtime, names: map[uint64]string{}, off: t}, nil
}

// currentFrame reads the thread's top frame, through _PyCFrame on 3.11 and 3.12.
func (p *pyWalker) currentFrame(ts uint64) (uint64, error) {
	cf, old := p.off["cframe"]
	if !old {
		return p.ptr(ts + p.off["curFrame"])
	}
	c, err := p.ptr(ts + cf)
	if err != nil {
		return 0, err
	}
	return p.ptr(c + p.off["cframeCur"])
}

// selfCheck proves the table against this build: the runtime is initialised, a thread points back
// at its interpreter (3.13+ has no table entry for those two, its cookie and version stand in) and a
// real code object is reached.
func (p *pyWalker) selfCheck() error {
	if o, old := p.off["initialized"]; old {
		var b [4]byte
		if err := p.mem.ReadAt(p.runtime+o, b[:]); err != nil {
			return err
		}
		if b[0] != 1 || b[1]|b[2]|b[3] != 0 {
			return errNotReady
		}
		interp, err := p.ptr(p.runtime + p.off["interpHead"])
		if err != nil {
			return err
		}
		if interp == 0 {
			return errNotReady
		}
		ts, err := p.ptr(interp + p.off["threadsHead"])
		if err != nil {
			return err
		}
		if ts == 0 {
			return errNotReady
		}
		back, err := p.ptr(ts + p.off["tsInterp"])
		if err != nil {
			return err
		}
		if back != interp {
			return errors.New("offset table mismatch: thread state does not point at its interpreter (debug or patched build?)")
		}
	}
	stacks, err := p.Stacks()
	if err != nil {
		return err
	}
	if len(stacks) == 0 {
		return errNotReady
	}
	return nil
}

func (p *pyWalker) resetNames() { p.names = map[uint64]string{} }
