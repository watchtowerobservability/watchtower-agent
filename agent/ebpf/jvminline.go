package ebpf

import (
	"errors"
	"runtime"
	"strings"
)

// Inlined frames. A compiled frame's pc maps to a PcDesc in its nmethod; the PcDesc's scope chain
// in the debug info names each method inlined at that pc, innermost first, ending at the
// nmethod's own method. Layouts, checked against openjdk vmStructs.cpp and nmethod.hpp: on
// JDK 17-22 the pcs are at blob + _scopes_pcs_offset, scopes at
// CompiledMethod::_scopes_data_begin, metadata at blob + _metadata_offset and code at
// CodeBlob::_code_begin. On JDK 23-24 pcs and scopes are at nmethod::_immutable_data plus their
// offsets, metadata at blob + CodeBlob::_data_offset + nmethod::_metadata_offset (u2) and code
// at blob + _code_offset. JDK 25+ is as 23, with metadata at CodeBlob::_mutable_data +
// _relocation_size. The stream's int encoding is the older Pack200 form on JDK 17 and UNSIGNED5 (no zero bytes)
// from JDK 21; both are tried, and a reading counts only when its outermost scope is the
// nmethod's own method. Anything else shows the outer method alone.
const (
	jvmPcLow     = 0xffffffff // PcDesc::lower_offset_limit (-1), the first record
	jvmPcHigh    = 0x7fffffff // PcDesc::upper_offset_limit, the last record
	jvmMaxPcs    = 1 << 14
	jvmPcChunk   = 64
	jvmMaxInline = 32
	jvmMaxMeta   = 1 << 16
)

// jvmInl holds where an nmethod keeps its debug info; ok is false when this build lacks a field.
type jvmInl struct {
	ok                                   bool
	codeBegin, codeOff, imm              jvmField // code start: address, or offset from the blob
	scopesBegin, scopesOff, pcsOff       jvmField
	metaOff, dataOff, mutable, reloc     jvmField
	pcSize, pcOffset, pcScope            uint64
	enc                                  int // chosen int encoding; -1 unknown
	hasCodeBegin, hasImm, hasScopesBegin bool
	hasMutable                           bool
}

// jvmDebug is one nmethod's PcDesc table and stream bases.
type jvmDebug struct {
	code, scopes, meta uint64
	pcs, scope         []uint32
}

func jvmTypeSize(t string) uint64 {
	switch t {
	case "int", "jint", "u4", "uint", "unsigned int", "int32_t", "uint32_t":
		return 4
	case "u2", "uint16_t", "int16_t", "short", "unsigned short", "jushort":
		return 2
	case "u1", "uint8_t", "char", "unsigned char", "bool", "jbyte":
		return 1
	case "address", "intptr_t", "uintptr_t", "size_t", "uint64_t", "int64_t", "jlong":
		return 8
	}
	if strings.HasSuffix(t, "*") {
		return 8
	}
	return 0
}

func newJVMInl(f map[string]jvmField, types map[string]uint64) jvmInl {
	in := jvmInl{enc: -1}
	get := func(names ...string) (jvmField, bool) {
		for _, n := range names {
			if v, ok := f[n]; ok && v.size != 0 {
				return v, true
			}
		}
		return jvmField{}, false
	}
	var okPcs, okMeta, okData, okReloc, okCodeOff, okScopesOff bool
	in.codeBegin, in.hasCodeBegin = get("CodeBlob::_code_begin")
	in.codeOff, okCodeOff = get("CodeBlob::_code_offset")
	in.imm, in.hasImm = get("nmethod::_immutable_data")
	in.scopesBegin, in.hasScopesBegin = get("CompiledMethod::_scopes_data_begin", "nmethod::_scopes_data_begin")
	in.scopesOff, okScopesOff = get("nmethod::_scopes_data_offset")
	in.pcsOff, okPcs = get("nmethod::_scopes_pcs_offset")
	in.metaOff, okMeta = get("nmethod::_metadata_offset")
	in.dataOff, okData = get("CodeBlob::_data_offset")
	in.mutable, in.hasMutable = get("CodeBlob::_mutable_data")
	in.reloc, okReloc = get("CodeBlob::_relocation_size")
	old := in.hasCodeBegin // JDK 17-22
	metaOK := (old && okMeta) || (!old && in.hasMutable && okReloc) || (!old && !in.hasMutable && okMeta && okData)
	pcOff, ok1 := f["PcDesc::_pc_offset"]
	pcScope, ok2 := f["PcDesc::_scope_decode_offset"]
	size, ok3 := types["PcDesc"]
	in.pcOffset, in.pcScope, in.pcSize = pcOff.offset, pcScope.offset, size
	in.ok = okPcs && metaOK && ok1 && ok2 && ok3 && size >= 8 && size <= 64 &&
		(in.hasCodeBegin || okCodeOff) && (in.hasScopesBegin || okScopesOff)
	return in
}

func (w *jvmWalker) field(at uint64, f jvmField) (uint64, error) {
	switch f.size {
	case 8:
		return w.m.u64(at + f.offset)
	case 4:
		v, err := w.m.u32(at + f.offset)
		return uint64(v), err
	case 2:
		v, err := w.m.u16(at + f.offset)
		return uint64(v), err
	case 1:
		v, err := w.m.u8(at + f.offset)
		return uint64(v), err
	}
	return 0, errors.New("field of unknown size")
}

// debugOf reads an nmethod's PcDesc table; nil when it fails the sentinel checks.
func (w *jvmWalker) debugOf(b *jvmBlob) *jvmDebug {
	in, at := &w.inl, b.at
	d := &jvmDebug{}
	var err error
	if in.hasCodeBegin {
		d.code, err = w.m.u64(at + in.codeBegin.offset)
	} else {
		d.code, err = w.field(at, in.codeOff)
		d.code += at
	}
	if err != nil {
		return nil
	}
	base := at
	if in.hasImm {
		if base, err = w.m.u64(at + in.imm.offset); err != nil || base == 0 {
			return nil
		}
	}
	if in.hasScopesBegin {
		d.scopes, err = w.m.u64(at + in.scopesBegin.offset)
	} else {
		d.scopes, err = w.field(at, in.scopesOff)
		d.scopes += base
	}
	pcsOff, e2 := w.field(at, in.pcsOff)
	var e3, e4 error
	switch {
	case in.hasCodeBegin:
		d.meta, e3 = w.field(at, in.metaOff)
		d.meta += at
	case in.hasMutable:
		var reloc uint64
		d.meta, e3 = w.m.u64(at + in.mutable.offset)
		reloc, e4 = w.field(at, in.reloc)
		d.meta += reloc
	default:
		var data uint64
		d.meta, e3 = w.field(at, in.metaOff)
		data, e4 = w.field(at, in.dataOff)
		d.meta += at + data
	}
	if errors.Join(err, e2, e3, e4) != nil {
		return nil
	}
	pcs := base + pcsOff
	buf := make([]byte, in.pcSize*jvmPcChunk)
	for i := uint64(0); i < jvmMaxPcs; i += jvmPcChunk {
		if w.m.ReadAt(pcs+i*in.pcSize, buf) != nil {
			return nil
		}
		for j := uint64(0); j < jvmPcChunk; j++ {
			r := buf[j*in.pcSize:]
			po, so := le32(r[in.pcOffset:]), le32(r[in.pcScope:])
			n := len(d.pcs)
			switch {
			case n == 0 && po != jvmPcLow:
				return nil // not a PcDesc table
			case n > 0 && po == jvmPcHigh:
				return d
			case n > 1 && po < d.pcs[n-1]:
				return nil // not sorted
			}
			d.pcs, d.scope = append(d.pcs, po), append(d.scope, so)
		}
	}
	return nil
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// jvmReadInt decodes one int of a debug info stream (utilities/unsigned5.hpp); x is the excluded
// byte count: 1 for UNSIGNED5 (JDK 21+), 0 for the older Pack200 form. ok is false past the buffer.
func jvmReadInt(b []byte, pos *int, x uint32) (uint32, bool) {
	const lgH, maxLen = 6, 5
	l := 256 - 64 - x
	if *pos >= len(b) {
		return 0, false
	}
	b0 := uint32(b[*pos])
	if b0 < x {
		return 0, false
	}
	sum := b0 - x
	if sum < l {
		*pos++
		return sum, true
	}
	for i, sh := 1, uint32(lgH); i < maxLen; i, sh = i+1, sh+lgH {
		if *pos+i >= len(b) {
			return 0, false
		}
		bi := uint32(b[*pos+i])
		if bi < x {
			return 0, false
		}
		sum += (bi - x) << sh
		if bi < x+l || i == maxLen-1 {
			*pos += i + 1
			return sum, true
		}
	}
	return 0, false
}

// chain reads the scope chain at off, innermost first, under one encoding.
func (w *jvmWalker) chain(d *jvmDebug, off uint32, x uint32, meta uint64, outer uint64) ([]string, bool) {
	var names []string
	buf := make([]byte, 16) // sender offset, method index, bci: at most 5 bytes each
	for range jvmMaxInline {
		if w.m.ReadAt(d.scopes+uint64(off), buf) != nil {
			return nil, false
		}
		pos := 0
		sender, ok1 := jvmReadInt(buf, &pos, x)
		idx, ok2 := jvmReadInt(buf, &pos, x)
		if !ok1 || !ok2 || idx == 0 || idx > jvmMaxMeta {
			return nil, false
		}
		m, err := w.m.u64(meta + uint64(idx-1)*8) // metadata indexes start at 1
		if err != nil {
			return nil, false
		}
		s, ok := w.methodName(m)
		if !ok {
			return nil, false
		}
		names = append(names, s)
		if sender == 0 { // serialized_null: this is the outermost scope
			return names, m == outer
		}
		off = sender
	}
	return nil, false
}

// compiledNames names a compiled frame with its inlined methods, or the outer method alone.
func (w *jvmWalker) compiledNames(b *jvmBlob, pc uint64) []string {
	if w.inl.ok && !b.debugRead {
		b.debug, b.debugRead = w.debugOf(b), true
	}
	if d := b.debug; d != nil && pc >= d.code {
		rel := pc - d.code
		for i := 1; i < len(d.pcs); i++ {
			if d.pcs[i] < uint32(min(rel, jvmPcHigh)) {
				continue
			}
			if d.scope[i] != 0 {
				if names := w.scopes(d, d.scope[i], b.method); names != nil {
					return names
				}
			}
			break
		}
	}
	if s, ok := w.methodName(b.method); ok {
		return []string{s}
	}
	return nil
}

// scopes tries each encoding until one reads, then keeps to it.
func (w *jvmWalker) scopes(d *jvmDebug, off uint32, outer uint64) []string {
	for enc := range 2 {
		if w.inl.enc >= 0 && enc != w.inl.enc {
			continue
		}
		if names, ok := w.chain(d, off, uint32(1-enc), d.meta, outer); ok {
			w.inl.enc = enc
			return names
		}
	}
	return nil
}

// jvmUpcall finds the Java frames below a JNI upcall: the call stub's entry frame holds a
// JavaCallWrapper, whose anchor saved the last Java frame before native code ran.
type jvmUpcall struct {
	ok           bool
	stubAt, stub uint64 // StubRoutines::_call_stub_return_address, and its value
	wrapperOff   int64  // frame::entry_frame_call_wrapper_offset, in words
	anchor       uint64 // JavaCallWrapper::_anchor
}

func newJVMUpcall(f map[string]jvmField, ints map[string]uint64) jvmUpcall {
	stub, ok1 := f["StubRoutines::_call_stub_return_address"]
	anchor, ok2 := f["JavaCallWrapper::_anchor"]
	u := jvmUpcall{ok: ok1 && ok2 && stub.static != 0, stubAt: stub.static, anchor: anchor.offset}
	if v, ok := ints["frame::entry_frame_call_wrapper_offset"]; ok {
		u.wrapperOff = int64(int32(uint32(v)))
	} else {
		switch runtime.GOARCH { // frame_<arch>.hpp, Linux
		case "amd64":
			u.wrapperOff = -6
		case "arm64":
			u.wrapperOff = -8
		default:
			u.ok = false
		}
	}
	return u
}

// isCallStub says pc is the return into the call stub. The stub is generated at startup, so its
// address is read until it is set.
func (w *jvmWalker) isCallStub(pc uint64) bool {
	if !w.up.ok {
		return false
	}
	if w.up.stub == 0 {
		v, err := w.m.u64(w.up.stubAt)
		if err != nil || v == 0 {
			return false
		}
		w.up.stub = v & jvmCodeMask
	}
	return pc == w.up.stub
}

// upcallSender is the last Java frame before the native code that called into Java at the entry
// frame fp; ok is false at the bottom of the thread (the VM called in, with no Java below).
func (w *jvmWalker) upcallSender(fp uint64) (sp, pc, nfp uint64, ok bool) {
	jcw, err := w.m.u64(uint64(int64(fp) + w.up.wrapperOff*8))
	if err != nil || jcw == 0 || jcw&7 != 0 {
		return 0, 0, 0, false
	}
	a := jcw + w.up.anchor
	sp, e1 := w.m.u64(a + w.lastSP)
	pc, e2 := w.m.u64(a + w.lastPC)
	nfp, e3 := w.m.u64(a + w.lastFP)
	if errors.Join(e1, e2, e3) != nil || sp == 0 {
		return 0, 0, 0, false
	}
	if pc == 0 {
		if pc, err = w.m.u64(sp - 8); err != nil {
			return 0, 0, 0, false
		}
	}
	return sp, pc, nfp, true
}
