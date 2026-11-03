package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"
)

// V8 ships its own layout in the v8dbg_* symbols of the node binary (postmortem metadata): nothing
// here is per-version except scopeName's decoding, which validates what it finds. V8 has no global
// reachable from outside for the current frame, so a stack starts from an on-CPU thread's frame
// pointer, sampled by rtregs.bpf.c. JS frames always keep frame pointers.
const (
	v8Tag             = 1
	v8TagMask         = 3
	v8MaxLocalsInline = 75 // kScopeInfoMaxInlinedLocalNamesSize, globals.h
	v8ScopeSavedClass = 1 << 10
	v8ScopeFnVarShift = 12 // 2 bits
	v8ScopeInferred   = 1 << 14
	v8SmiShift        = 32
	v8MaxStringDepth  = 4
)

type nodeWalker struct {
	m     rmem
	o     nodeOffsets
	alive uint64            // a mapped address: read each tick to notice the process is gone
	names map[uint64]string // SharedFunctionInfo -> frame name
}

type nodeOffsets struct {
	fpContext, fpFunction                               int64
	mapOf, instType, jsShared, sfiName, sfiScript       uint64
	scriptName, strLen, seqChars, consFirst, consSecond uint64
	thinActual                                          uint64
	firstJSFn, lastJSFn, firstNonString, scopeInfo      uint64
	script, encMask, oneByte, repMask, seq, cons, thin  uint64
}

// v8Lookup finds a symbol's value by exact name or by name prefix: the type suffix of a class
// field changes between V8 versions.
type v8Lookup func(name string) (int64, bool)

func newNodeWalker(mem memReader, get v8Lookup, alive uint64) (*nodeWalker, error) {
	var o nodeOffsets
	var missing []string
	i := func(name string, dst *int64) {
		v, ok := get(name)
		if !ok {
			missing = append(missing, name)
		}
		*dst = v
	}
	u := func(name string, dst *uint64) {
		var v int64
		i(name, &v)
		*dst = uint64(v)
	}
	i("off_fp_context", &o.fpContext)
	i("off_fp_function", &o.fpFunction)
	for name, dst := range map[string]*uint64{
		"class_HeapObject__map__": &o.mapOf, "class_Map__instance_type__": &o.instType,
		"class_JSFunction__shared__": &o.jsShared, "class_SharedFunctionInfo__name_or_scope_info__": &o.sfiName,
		"class_SharedFunctionInfo__script__": &o.sfiScript, "class_Script__name__": &o.scriptName,
		"class_String__length__": &o.strLen, "class_SeqOneByteString__chars__": &o.seqChars,
		"class_ConsString__first__": &o.consFirst, "class_ConsString__second__": &o.consSecond,
		"class_ThinString__actual__": &o.thinActual, "FirstJSFunctionType": &o.firstJSFn, "LastJSFunctionType": &o.lastJSFn,
		"FirstNonstringType": &o.firstNonString, "type_ScopeInfo__SCOPE_INFO_TYPE": &o.scopeInfo,
		"type_Script__SCRIPT_TYPE": &o.script, "StringEncodingMask": &o.encMask, "OneByteStringTag": &o.oneByte,
		"StringRepresentationMask": &o.repMask, "SeqStringTag": &o.seq, "ConsStringTag": &o.cons, "ThinStringTag": &o.thin,
	} {
		u(name, dst)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("V8 metadata lacks %s (stripped or newer build)", strings.Join(missing, ", "))
	}
	if t, ok := get("TaggedSize"); !ok || t != 8 {
		return nil, fmt.Errorf("V8 tagged size %d: pointer-compressed builds are refused", t)
	}
	if t, ok := get("HeapObjectTag"); !ok || t != v8Tag {
		return nil, fmt.Errorf("V8 heap object tag %d is not %d", t, v8Tag)
	}
	return &nodeWalker{m: rmem{mem}, o: o, alive: alive, names: map[uint64]string{}}, nil
}

// selfCheck: there is no object to read before a sample, so it checks the metadata's own shape.
// Every object read later is checked against its instance type.
func (n *nodeWalker) selfCheck() error {
	o := n.o
	if o.fpFunction >= 0 || o.fpContext >= 0 || o.firstJSFn > o.lastJSFn || o.lastJSFn > 0xffff || o.instType > 64 {
		return errors.New("V8 metadata has implausible values")
	}
	return nil
}

// Stacks has nothing to read without registers; it only notices that the process is gone.
func (n *nodeWalker) Stacks() ([]PyStack, error) {
	_, err := n.m.u8(n.alive)
	return nil, err
}

func (n *nodeWalker) resetNames() { n.names = map[uint64]string{} }

// field reads a tagged field; the offsets are from the object's untagged start.
func (n *nodeWalker) field(obj, off uint64) (uint64, error) { return n.m.u64(obj - v8Tag + off) }

func isHeap(v uint64) bool { return v&v8TagMask == v8Tag }

func (n *nodeWalker) typeOf(obj uint64) (uint64, error) {
	if !isHeap(obj) {
		return 0, errors.New("not a heap object")
	}
	mp, err := n.field(obj, n.o.mapOf)
	if err != nil {
		return 0, err
	}
	if !isHeap(mp) {
		return 0, errors.New("bad map")
	}
	t, err := n.m.u16(mp - v8Tag + n.o.instType)
	return uint64(t), err
}

func (n *nodeWalker) str(obj uint64, depth int) (string, error) {
	t, err := n.typeOf(obj)
	if err != nil {
		return "", err
	}
	if t >= n.o.firstNonString {
		return "", errors.New("not a string")
	}
	if depth >= v8MaxStringDepth {
		return "", errors.New("string nests too deep")
	}
	switch t & n.o.repMask {
	case n.o.thin:
		a, err := n.field(obj, n.o.thinActual)
		if err != nil {
			return "", err
		}
		return n.str(a, depth+1)
	case n.o.cons:
		f, e1 := n.field(obj, n.o.consFirst)
		s, e2 := n.field(obj, n.o.consSecond)
		if e1 != nil || e2 != nil {
			return "", errors.Join(e1, e2)
		}
		a, e1 := n.str(f, depth+1)
		b, e2 := n.str(s, depth+1)
		if e1 != nil || e2 != nil {
			return "", errors.Join(e1, e2)
		}
		return a + b, nil
	case n.o.seq:
	default:
		return "?", nil // external strings need more of the heap
	}
	if t&n.o.encMask != n.o.oneByte {
		return "?", nil // two-byte names
	}
	l, err := n.m.u32(obj - v8Tag + n.o.strLen)
	if err != nil {
		return "", err
	}
	b := make([]byte, min(l, rtMaxString))
	if err := n.m.ReadAt(obj-v8Tag+n.o.seqChars, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// scopeName finds a function's name in its ScopeInfo. The layout is torque-generated and not in
// the metadata, so this reads it from scope-info.tq: Node 22 has Smi flags and its position info
// later; Node 24 and newer have uint32 flags, padding, and position info first. The first word
// tells them apart, and only a value that passes as a String is used, so a future layout gives an
// anonymous frame, not garbage.
func (n *nodeWalker) scopeName(si uint64) string {
	base := si - v8Tag + 8
	head, err := n.m.u64(base)
	if err != nil {
		return ""
	}
	count, err := n.m.u64(base + 16)
	if err != nil || uint32(count) != 0 || count>>v8SmiShift > 1<<16 {
		return ""
	}
	flags, slot := head>>v8SmiShift, base+24
	if uint32(head) != 0 {
		flags, slot = head&0xffffffff, base+40
	}
	locals := count >> v8SmiShift
	slot += 8 * locals // context_local_infos
	if locals < v8MaxLocalsInline {
		slot += 8 * locals // context_local_names
	} else {
		slot += 8 // their hash table
	}
	if flags&v8ScopeSavedClass != 0 {
		slot += 8
	}
	if flags>>v8ScopeFnVarShift&3 != 0 {
		if s := n.slotString(slot); s != "" {
			return s
		}
		slot += 16 // FunctionVariableInfo is the name and a slot index
	}
	if flags&v8ScopeInferred != 0 {
		return n.slotString(slot)
	}
	return ""
}

func (n *nodeWalker) slotString(at uint64) string {
	v, err := n.m.u64(at)
	if err != nil || !isHeap(v) {
		return ""
	}
	s, err := n.str(v, 0)
	if err != nil {
		return ""
	}
	return s
}

// frameName is `fn (file.js)` from a JSFunction; ok is false when obj is not one.
func (n *nodeWalker) frameName(fn uint64) (string, bool) {
	t, err := n.typeOf(fn)
	if err != nil || t < n.o.firstJSFn || t > n.o.lastJSFn {
		return "", false
	}
	sfi, err := n.field(fn, n.o.jsShared)
	if err != nil || !isHeap(sfi) {
		return "", false
	}
	if s, ok := n.names[sfi]; ok {
		return s, true
	}
	name := ""
	if v, err := n.field(sfi, n.o.sfiName); err == nil && isHeap(v) {
		if vt, err := n.typeOf(v); err == nil {
			if vt == n.o.scopeInfo {
				name = n.scopeName(v)
			} else if vt < n.o.firstNonString {
				name, _ = n.str(v, 0)
			}
		}
	}
	if name == "" {
		name = "(anonymous)"
	}
	if sc, err := n.field(sfi, n.o.sfiScript); err == nil {
		if st, err := n.typeOf(sc); err == nil && st == n.o.script {
			if v, err := n.field(sc, n.o.scriptName); err == nil {
				if f, err := n.str(v, 0); err == nil && f != "" {
					name += " (" + path.Base(f) + ")"
				}
			}
		}
	}
	if !printable(name) {
		return "", false
	}
	name = strings.ReplaceAll(name, ";", ":")
	n.names[sfi] = name
	return name, true
}

// StackFrom follows the frame pointer chain: a slot holding a JSFunction, in a frame whose context
// slot is not a frame-type marker (a Smi), is a JS frame. C++ frames between them are skipped when
// they keep a frame pointer, and the chain ends where they do not.
func (n *nodeWalker) StackFrom(_, _, fp uint64) []string {
	var out []string
	low := -min(n.o.fpFunction, n.o.fpContext)
	buf := make([]byte, uint64(low)+8)
	start := fp
	for len(out) < rtMaxFrames && fp != 0 && fp-start < rtStackSpan {
		if err := n.m.ReadAt(fp-uint64(low), buf); err != nil {
			break
		}
		slot := func(off int64) uint64 { return binary.LittleEndian.Uint64(buf[off+low:]) }
		if isHeap(slot(n.o.fpContext)) {
			if s, ok := n.frameName(slot(n.o.fpFunction)); ok {
				out = append(out, s)
			}
		}
		next := slot(0)
		if next <= fp { // a stack grows down: the caller's frame is higher
			break
		}
		fp = next
	}
	return out
}
