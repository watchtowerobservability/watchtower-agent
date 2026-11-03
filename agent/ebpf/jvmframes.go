package ebpf

import (
	"errors"
	"fmt"
	"strings"
)

// HotSpot publishes its layout for the Serviceability Agent: gHotSpotVMStructs lists every field
// the walker needs, per build. Nothing here is per-version except the two names of nmethod's
// method field. A build that lacks a field is refused and the field named (JDK 8 keeps its threads
// elsewhere, so it fails on ThreadsSMRSupport).
//
// A thread outside Java code has a frame anchor, and its stack is read from that at any time. A
// thread in Java code clears its anchor, so its stack starts from a BPF sample's registers.
//
// Inlined methods are read from the nmethod's debug info (jvminline.go). A walk that reaches the
// call stub (native code calling back into Java) goes on from JavaCallWrapper's saved anchor.
const (
	jvmInterpMethod   = 3 * 8 // frame::interpreter_frame_method_offset = -3 words, x86 and aarch64
	jvmInterpSenderSP = 1 * 8 // frame::interpreter_frame_sender_sp_offset = -1 word
	jvmMaxStructs     = 8192
	jvmMaxHeaps       = 16
	jvmMaxSegSteps    = 128
	jvmSegFree        = 0xff
	jvmCodeMask       = 0x0000ffffffffffff // strips aarch64 pointer authentication
)

type jvmField struct {
	offset uint64
	static uint64 // address, for static fields
	size   uint64 // from the field's C type; 0 when unknown
}

// jvmSyms holds the addresses of the exported gHotSpotVM* variables.
type jvmSyms map[string]uint64

func (m rmem) deref(s jvmSyms, name string) (uint64, error) {
	a, ok := s[name]
	if !ok {
		return 0, errors.New("libjvm does not export " + name)
	}
	return m.u64(a)
}

// readVMStructs parses the struct table into "Type::field".
func readVMStructs(m rmem, s jvmSyms) (map[string]jvmField, error) {
	vals := map[string]uint64{}
	for _, n := range []string{"gHotSpotVMStructs", "gHotSpotVMStructEntryTypeNameOffset", "gHotSpotVMStructEntryFieldNameOffset", "gHotSpotVMStructEntryIsStaticOffset", "gHotSpotVMStructEntryOffsetOffset", "gHotSpotVMStructEntryAddressOffset", "gHotSpotVMStructEntryArrayStride"} {
		v, err := m.deref(s, n)
		if err != nil {
			return nil, err
		}
		vals[n] = v
	}
	if vals["gHotSpotVMStructs"] == 0 {
		return nil, errNotReady
	}
	typeOff, hasType := s["gHotSpotVMStructEntryTypeStringOffset"]
	if hasType {
		if typeOff, err := m.u64(typeOff); err == nil {
			vals["typeString"] = typeOff
		} else {
			hasType = false
		}
	}
	stride := vals["gHotSpotVMStructEntryArrayStride"]
	if stride == 0 || stride > 256 {
		return nil, fmt.Errorf("implausible VMStruct stride %d", stride)
	}
	out := map[string]jvmField{}
	for i := uint64(0); i < jvmMaxStructs; i++ {
		e := vals["gHotSpotVMStructs"] + i*stride
		tn, err := m.u64(e + vals["gHotSpotVMStructEntryTypeNameOffset"])
		if err != nil {
			return nil, err
		}
		if tn == 0 {
			return out, nil
		}
		fn, err := m.u64(e + vals["gHotSpotVMStructEntryFieldNameOffset"])
		if err != nil {
			return nil, err
		}
		t, e1 := m.cstr(tn, 128)
		f, e2 := m.cstr(fn, 128)
		st, e3 := m.u32(e + vals["gHotSpotVMStructEntryIsStaticOffset"])
		off, e4 := m.u64(e + vals["gHotSpotVMStructEntryOffsetOffset"])
		ad, e5 := m.u64(e + vals["gHotSpotVMStructEntryAddressOffset"])
		if err := errors.Join(e1, e2, e3, e4, e5); err != nil {
			return nil, err
		}
		fd := jvmField{offset: off}
		if st != 0 {
			fd = jvmField{static: ad}
		}
		if hasType {
			if tp, err := m.u64(e + vals["typeString"]); err == nil && tp != 0 {
				if ts, err := m.cstr(tp, 128); err == nil {
					fd.size = jvmTypeSize(ts)
				}
			}
		}
		out[t+"::"+f] = fd
	}
	return nil, errors.New("VMStruct table has no end")
}

// readVMTable reads a name -> value table (gHotSpotVMTypes sizes, gHotSpotVMIntConstants values).
func readVMTable(m rmem, s jvmSyms, base, nameOff, valOff, stride string, wide bool) (map[string]uint64, error) {
	vals := map[string]uint64{}
	for _, n := range []string{base, nameOff, valOff, stride} {
		v, err := m.deref(s, n)
		if err != nil {
			return nil, err
		}
		vals[n] = v
	}
	if vals[stride] == 0 || vals[stride] > 256 {
		return nil, fmt.Errorf("implausible %s %d", stride, vals[stride])
	}
	out := map[string]uint64{}
	for i := uint64(0); i < jvmMaxStructs; i++ {
		e := vals[base] + i*vals[stride]
		nm, err := m.u64(e + vals[nameOff])
		if err != nil {
			return nil, err
		}
		if nm == 0 {
			return out, nil
		}
		name, err := m.cstr(nm, 128)
		if err != nil {
			return nil, err
		}
		if wide {
			out[name], err = m.u64(e + vals[valOff])
		} else {
			var v uint32
			v, err = m.u32(e + vals[valOff])
			out[name] = uint64(v)
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New(base + " has no end")
}

type jvmHeap struct {
	low, high, segmap, log2 uint64
}

type jvmBlob struct {
	nmethod, interp bool
	at, method      uint64
	frameWords      uint64
	debug           *jvmDebug // inlining info, read on first use
	debugRead       bool
}

type jvmWalker struct {
	m                                                rmem
	threadList                                       uint64 // address of ThreadsSMRSupport::_java_thread_list
	listLen, listArr, anchor, lastSP, lastPC, lastFP uint64
	state, inJava, blobName, blobFrame, nmMethod     uint64
	constMethod, constants, nameIdx, poolHolder      uint64
	klassName, symLen, symBody, poolSize, heapBlock  uint64
	heaps                                            []jvmHeap
	inl                                              jvmInl
	up                                               jvmUpcall
	blobs                                            map[uint64]*jvmBlob
	names                                            map[uint64]string
}

func newJVMWalker(mem memReader, s jvmSyms) (*jvmWalker, error) {
	m := rmem{mem}
	f, err := readVMStructs(m, s)
	if err != nil {
		return nil, err
	}
	types, err := readVMTable(m, s, "gHotSpotVMTypes", "gHotSpotVMTypeEntryTypeNameOffset", "gHotSpotVMTypeEntrySizeOffset", "gHotSpotVMTypeEntryArrayStride", true)
	if err != nil {
		return nil, err
	}
	ints, err := readVMTable(m, s, "gHotSpotVMIntConstants", "gHotSpotVMIntConstantEntryNameOffset", "gHotSpotVMIntConstantEntryValueOffset", "gHotSpotVMIntConstantEntryArrayStride", false)
	if err != nil {
		return nil, err
	}
	w := &jvmWalker{m: m, blobs: map[uint64]*jvmBlob{}, names: map[uint64]string{}}
	var missing []string
	off := func(name string) uint64 {
		v, ok := f[name]
		if !ok {
			missing = append(missing, name)
		}
		return v.offset
	}
	nm, ok := f["nmethod::_method"]
	if !ok {
		nm, ok = f["CompiledMethod::_method"] // before JDK 23
	}
	if !ok {
		missing = append(missing, "nmethod::_method")
	}
	w.nmMethod = nm.offset
	tl, ok := f["ThreadsSMRSupport::_java_thread_list"]
	if !ok {
		missing = append(missing, "ThreadsSMRSupport::_java_thread_list")
	}
	w.threadList = tl.static
	w.listLen, w.listArr = off("ThreadsList::_length"), off("ThreadsList::_threads")
	w.anchor, w.state = off("JavaThread::_anchor"), off("JavaThread::_thread_state")
	w.lastSP, w.lastPC, w.lastFP = off("JavaFrameAnchor::_last_Java_sp"), off("JavaFrameAnchor::_last_Java_pc"), off("JavaFrameAnchor::_last_Java_fp")
	w.blobName, w.blobFrame = off("CodeBlob::_name"), off("CodeBlob::_frame_size")
	w.constMethod, w.constants, w.nameIdx = off("Method::_constMethod"), off("ConstMethod::_constants"), off("ConstMethod::_name_index")
	w.poolHolder, w.klassName = off("ConstantPool::_pool_holder"), off("Klass::_name")
	w.symLen, w.symBody = off("Symbol::_length"), off("Symbol::_body")
	heaps, hOK := f["CodeCache::_heaps"]
	memOff, segOff, logOff := off("CodeHeap::_memory"), off("CodeHeap::_segmap"), off("CodeHeap::_log2_segment_size")
	lowOff, highOff := off("VirtualSpace::_low"), off("VirtualSpace::_high")
	gaLen, gaData := off("GrowableArrayBase::_len"), off("GrowableArray<int>::_data")
	if !hOK {
		missing = append(missing, "CodeCache::_heaps")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("HotSpot VMStructs lacks %s (JDK 8 or a changed build)", strings.Join(missing, ", "))
	}
	var tOK, iOK bool
	if w.poolSize, tOK = types["ConstantPool"]; !tOK {
		return nil, errors.New("HotSpot VMTypes lacks ConstantPool")
	}
	if w.heapBlock, tOK = types["HeapBlock"]; !tOK {
		return nil, errors.New("HotSpot VMTypes lacks HeapBlock")
	}
	if w.inJava, iOK = ints["_thread_in_Java"]; !iOK {
		return nil, errors.New("HotSpot VMIntConstants lacks _thread_in_Java")
	}
	w.inl = newJVMInl(f, types)
	w.up = newJVMUpcall(f, ints)
	return w, w.readHeaps(heaps.static, gaLen, gaData, memOff, segOff, logOff, lowOff, highOff)
}

func (w *jvmWalker) readHeaps(heapsAt, gaLen, gaData, memOff, segOff, logOff, lowOff, highOff uint64) error {
	ga, err := w.m.u64(heapsAt)
	if err != nil {
		return err
	}
	if ga == 0 {
		return errNotReady
	}
	n, e1 := w.m.u32(ga + gaLen)
	data, e2 := w.m.u64(ga + gaData)
	if err := errors.Join(e1, e2); err != nil {
		return err
	}
	if n == 0 || n > jvmMaxHeaps {
		return fmt.Errorf("implausible code heap count %d", n)
	}
	for i := uint64(0); i < uint64(n); i++ {
		h, err := w.m.u64(data + i*8)
		if err != nil {
			return err
		}
		low, e1 := w.m.u64(h + memOff + lowOff)
		high, e2 := w.m.u64(h + memOff + highOff)
		seg, e3 := w.m.u64(h + segOff + lowOff)
		lg, e4 := w.m.u32(h + logOff)
		if err := errors.Join(e1, e2, e3, e4); err != nil {
			return err
		}
		if low == 0 || low >= high || seg == 0 || lg < 3 || lg > 16 {
			return fmt.Errorf("implausible code heap: low %#x high %#x log2 %d", low, high, lg)
		}
		w.heaps = append(w.heaps, jvmHeap{low, high, seg, uint64(lg)})
	}
	return nil
}

// selfCheck reads the thread list; the fields themselves came from the target's own table.
func (w *jvmWalker) selfCheck() error {
	if w.heapBlock == 0 || w.heapBlock > 64 || w.poolSize == 0 || w.poolSize > 1024 {
		return errors.New("HotSpot VMTypes has implausible sizes")
	}
	tl, err := w.m.u64(w.threadList)
	if err != nil {
		return err
	}
	if tl == 0 {
		return errNotReady
	}
	n, err := w.m.u32(tl + w.listLen)
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotReady
	}
	if n > 1<<20 {
		return fmt.Errorf("implausible thread count %d", n)
	}
	return nil
}

func (w *jvmWalker) resetNames() {
	w.names = map[uint64]string{}
	w.blobs = map[uint64]*jvmBlob{}
}

// blobAt finds the code blob holding pc through the code heap's segment map, the way CodeHeap's
// find_start does; nil when pc is not in compiled or interpreter code.
func (w *jvmWalker) blobAt(pc uint64) *jvmBlob {
	for _, h := range w.heaps {
		if pc < h.low || pc >= h.high {
			continue
		}
		i := (pc - h.low) >> h.log2
		for steps := 0; steps < jvmMaxSegSteps; steps++ {
			b, err := w.m.u8(h.segmap + i)
			if err != nil || b == jvmSegFree {
				return nil
			}
			if b == 0 {
				return w.blob(h.low + i<<h.log2 + w.heapBlock)
			}
			if uint64(b) > i {
				return nil
			}
			i -= uint64(b)
		}
		return nil
	}
	return nil
}

func (w *jvmWalker) blob(at uint64) *jvmBlob {
	if b, ok := w.blobs[at]; ok {
		return b
	}
	np, err := w.m.u64(at + w.blobName)
	if err != nil {
		return nil
	}
	name, err := w.m.cstr(np, 64)
	if err != nil {
		return nil
	}
	fs, err := w.m.u32(at + w.blobFrame)
	if err != nil || fs > 1<<20 {
		return nil
	}
	b := &jvmBlob{at: at, interp: name == "Interpreter", nmethod: strings.Contains(name, "nmethod"), frameWords: uint64(fs)}
	if b.nmethod {
		if b.method, err = w.m.u64(at + w.nmMethod); err != nil {
			return nil
		}
	}
	w.blobs[at] = b
	return b
}

func (w *jvmWalker) symbol(sym uint64) (string, bool) {
	n, err := w.m.u16(sym + w.symLen)
	if err != nil || n == 0 || n > rtMaxString {
		return "", false
	}
	b := make([]byte, n)
	if w.m.ReadAt(sym+w.symBody, b) != nil {
		return "", false
	}
	s := string(b)
	return s, printable(s)
}

// methodName is `pkg.Class.method`. Each step must land on a real symbol, so a torn Method gives
// no frame rather than a wrong name of arbitrary bytes.
func (w *jvmWalker) methodName(m uint64) (string, bool) {
	if s, ok := w.names[m]; ok {
		return s, true
	}
	if m == 0 || m&7 != 0 {
		return "", false
	}
	cm, err := w.m.u64(m + w.constMethod)
	if err != nil {
		return "", false
	}
	cp, err := w.m.u64(cm + w.constants)
	if err != nil {
		return "", false
	}
	idx, err := w.m.u16(cm + w.nameIdx)
	if err != nil {
		return "", false
	}
	nameSym, err := w.m.u64(cp + w.poolSize + uint64(idx)*8)
	if err != nil {
		return "", false
	}
	k, err := w.m.u64(cp + w.poolHolder)
	if err != nil {
		return "", false
	}
	cls, err := w.m.u64(k + w.klassName)
	if err != nil {
		return "", false
	}
	mn, ok1 := w.symbol(nameSym)
	cn, ok2 := w.symbol(cls)
	if !ok1 || !ok2 {
		return "", false
	}
	s := strings.ReplaceAll(strings.ReplaceAll(cn, "/", "."), ";", ":") + "." + strings.ReplaceAll(mn, ";", ":")
	w.names[m] = s
	return s, true
}

// StackFrom walks Java frames from registers. Every step needs its pc in the code heaps and a
// higher sp, so a stale start ends at once.
func (w *jvmWalker) StackFrom(pc, sp, fp uint64) []string {
	var out []string
	start := sp
	for len(out) < rtMaxFrames && sp-start < rtStackSpan {
		if w.isCallStub(pc & jvmCodeMask) {
			nsp, npc, nfp, ok := w.upcallSender(fp)
			if !ok || nsp <= sp {
				break
			}
			pc, sp, fp = npc, nsp, nfp
			continue
		}
		b := w.blobAt(pc & jvmCodeMask)
		if b == nil {
			break
		}
		var nsp, npc, nfp uint64
		var e1, e2, e3 error
		switch {
		case b.interp:
			m, err := w.m.u64(fp - jvmInterpMethod)
			if err != nil {
				return out
			}
			if s, ok := w.methodName(m); ok {
				out = append(out, s)
			}
			nsp, e1 = w.m.u64(fp - jvmInterpSenderSP)
			npc, e2 = w.m.u64(fp + 8)
			nfp, e3 = w.m.u64(fp)
		case b.frameWords > 0:
			if b.nmethod {
				out = append(out, w.compiledNames(b, pc&jvmCodeMask)...)
			}
			nsp = sp + b.frameWords*8
			npc, e2 = w.m.u64(nsp - 8)
			nfp, e3 = w.m.u64(nsp - 16)
		default:
			return out // another stub or an adapter without a frame size
		}
		if errors.Join(e1, e2, e3) != nil || nsp <= sp {
			break
		}
		pc, sp, fp = npc, nsp, nfp
	}
	return out[:min(len(out), rtMaxFrames)]
}

// Stacks reads the threads outside Java code from their anchors.
func (w *jvmWalker) Stacks() ([]PyStack, error) {
	tl, err := w.m.u64(w.threadList)
	if err != nil {
		return nil, err
	}
	if tl == 0 {
		return nil, nil
	}
	n, e1 := w.m.u32(tl + w.listLen)
	arr, e2 := w.m.u64(tl + w.listArr)
	if err := errors.Join(e1, e2); err != nil {
		return nil, err
	}
	var out []PyStack
	for i := uint64(0); i < min(uint64(n), rtMaxThreads); i++ {
		t, err := w.m.u64(arr + i*8)
		if err != nil {
			break
		}
		if st, err := w.m.u32(t + w.state); err != nil || uint64(st) == w.inJava {
			continue
		}
		sp, e1 := w.m.u64(t + w.anchor + w.lastSP)
		pc, e2 := w.m.u64(t + w.anchor + w.lastPC)
		fp, e3 := w.m.u64(t + w.anchor + w.lastFP)
		if errors.Join(e1, e2, e3) != nil || sp == 0 {
			continue
		}
		if pc == 0 {
			if pc, err = w.m.u64(sp - 8); err != nil {
				continue
			}
		}
		if fr := w.StackFrom(pc, sp, fp); len(fr) > 0 {
			out = append(out, PyStack{Thread: t, Frames: fr})
		}
	}
	return out, nil
}
