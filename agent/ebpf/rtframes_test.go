package ebpf

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func (m fakeMem) u32(a uint64, v uint32) { m.put(a, binary.LittleEndian.AppendUint32(nil, v)) }
func (m fakeMem) u16(a uint64, v uint16) { m.put(a, binary.LittleEndian.AppendUint16(nil, v)) }

func TestBudgetEndsAWalk(t *testing.T) {
	m := fakeMem{}
	m.u64(0x10, 1)
	left := 1
	b := &budgetMem{m, &left}
	if _, err := (rmem{b}).u64(0x10); err != nil {
		t.Fatal(err)
	}
	if _, err := (rmem{b}).u64(0x10); !errors.Is(err, errBudget) {
		t.Fatalf("err %v", err)
	}
}

func TestCPUGuardLowersReadCaps(t *testing.T) {
	// Rate already at its floor: the readers must still be governed.
	g := Guard{Budget: 0.01, Rate: 1}
	if rtReadCap(g.Cuts) != rtTickReads {
		t.Fatalf("uncut cap %d", rtReadCap(g.Cuts))
	}
	g.Observe(0.1, 60) // under budget
	if g.Cuts != 0 {
		t.Fatal("under budget must not cut")
	}
	g.Observe(60, 60)
	m := fakeMem{}
	m.u64(0x10, 1)
	left := rtReadCap(g.Cuts)
	if left != rtTickReads/2 {
		t.Fatalf("one cut gives %d", left)
	}
	b := rmem{&budgetMem{m, &left}}
	reads := 0
	for ; ; reads++ {
		if _, err := b.u64(0x10); err != nil {
			break
		}
	}
	if reads != rtTickReads/2 {
		t.Fatalf("walk made %d reads", reads)
	}
	for range 80 {
		g.Observe(60, 60)
	}
	if rtReadCap(g.Cuts) != rtMinTickReads {
		t.Fatalf("floor %d", rtReadCap(g.Cuts))
	}
}

func TestPyOldTableSelfCheckAndRefusals(t *testing.T) {
	const rt, interp, ts, cf, fr, code, typ, tn, q, f = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x7800, 0x8000, 0x9000
	o := pyOldTables[12]
	m := fakeMem{}
	m.put(rt, []byte("notcookie"))
	m.u32(rt+o["initialized"], 1)
	m.u64(rt+o["interpHead"], interp)
	m.u64(interp+o["interpNext"], 0)
	m.u64(interp+o["threadsHead"], ts)
	m.u64(ts+o["threadNext"], 0)
	m.u64(ts+o["tsInterp"], interp)
	m.u64(ts+o["nativeTid"], 5)
	m.u64(ts+o["cframe"], cf)
	m.u64(cf+o["cframeCur"], fr)
	m.put(fr+o["frameOwner"], []byte{0})
	m.u64(fr+o["frameExec"], code)
	m.u64(fr+o["framePrev"], 0)
	m.u64(code+o["obType"], typ)
	m.u64(typ+o["tpName"], tn)
	m.put(tn, []byte("code\x00"))
	m.u64(code+o["codeQualname"], q)
	m.u64(code+o["codeFilename"], f)
	for s, v := range map[uint64]string{q: "go", f: "/x/a.py"} {
		m.u32(s+o["uniState"], pyCompactASCII)
		m.u64(s+o["uniLen"], uint64(len(v)))
		m.put(s+o["uniASCII"], []byte(v))
	}
	const v312 = 0x030c07f0
	p, err := newPyWalkerFor(m, rt, v312, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.selfCheck(); err != nil {
		t.Fatal(err)
	}
	st, _ := p.Stacks()
	if len(st) != 1 || st[0].Frames[0] != "go (a.py)" {
		t.Fatalf("stacks %+v", st)
	}
	// A wrong table: the thread no longer points at its interpreter.
	m.u64(ts+o["tsInterp"], 0xbad)
	if err := p.selfCheck(); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("err %v", err)
	}
	if _, err := newPyWalkerFor(m, rt, v312, false); err == nil || !strings.Contains(err.Error(), "python_legacy") {
		t.Fatalf("3.12 without the opt-in: %v", err)
	}
	if _, err := newPyWalkerFor(m, rt, 0x030a00f0, true); err == nil {
		t.Fatal("3.10 must be refused")
	}
	if _, err := newPyWalkerFor(m, rt, 0, true); err == nil {
		t.Fatal("no version must be refused")
	}
}

func TestPyFreeThreadedIsRefusedWithItsReason(t *testing.T) {
	m := fakeMem{}
	m.put(0x10, []byte("xdebugpy"))
	m.u64(0x18, 0x030e00f0)
	m.u64(0x20, 1)
	if _, err := newPyWalkerFor(m, 0x10, 0, false); !errors.Is(err, errFreeThreaded) {
		t.Fatalf("err %v", err)
	}
}

func rubyString(m fakeMem, at uint64, s string) {
	l := rubyRow
	m.u64(at, l.tString)
	m.u64(at+l.strLen, uint64(len(s)))
	m.put(at+l.strEmbed, []byte(s))
}

func TestRubyWalker(t *testing.T) {
	const vmp, vm, th, ec, stack, iseq, body, label, pathv, head = 0x100, 0x200, 0x300, 0x400, 0x10000, 0x500, 0x600, 0x700, 0x800, 0x900
	l := rubyRow
	m := fakeMem{}
	m.u64(vmp, vm)
	m.u64(vm+l.vmMainThread, th)
	m.u64(th, head) // list: thread -> head of the list in the ractor -> thread
	m.u64(th+l.thVM, vm)
	m.u64(th+l.thRactor, 0x77)
	m.u64(th+l.thEC, ec)
	m.u64(head, th)
	m.u64(head+l.thRactor, 0)
	size := uint64(1024)
	end := uint64(stack) + size*8
	cfp := end - 2*l.cfpSize
	m.u64(ec+l.ecVMStack, stack)
	m.u64(ec+l.ecVMStackSize, size)
	m.u64(ec+l.ecCFP, cfp)
	m.u64(cfp+l.cfpIseq, iseq)
	m.u64(cfp+l.cfpSize+l.cfpIseq, 0) // a C frame
	m.u64(iseq, l.tImemo|l.imemoIseq<<l.fieldUShift)
	m.u64(iseq+l.iseqBody, body)
	m.u64(body+l.bodyLabel, label)
	m.u64(body+l.bodyPathobj, pathv)
	rubyString(m, label, "Foo#bar")
	rubyString(m, pathv, "/app/foo.rb")
	r, err := newRubyWalker(m, vmp, "3.4.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.selfCheck(); err != nil {
		t.Fatal(err)
	}
	st, err := r.Stacks()
	if err != nil || !reflect.DeepEqual(st, []PyStack{{Thread: th, Frames: []string{"Foo#bar (foo.rb)"}}}) {
		t.Fatalf("%+v %v", st, err)
	}
	r.resetNames()
	m.u64(ec+l.ecCFP, cfp+8) // not a whole number of frames from the end
	if err := r.selfCheck(); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("err %v", err)
	}
	m.u64(ec+l.ecCFP, cfp)
	m.u64(iseq, 0xdead) // torn: not an imemo
	if st, _ := r.Stacks(); len(st) != 0 {
		t.Fatalf("a torn iseq gave %+v", st)
	}
	if _, err := newRubyWalker(m, vmp, "3.2.9"); err == nil {
		t.Fatal("EOL Ruby must be refused")
	}
	m.u64(th, th) // a self-loop stays bounded
	if _, err := r.Stacks(); err != nil {
		t.Fatal(err)
	}
}

// Two ractors: the second is found through the VM's ractor list, with both list offsets taken
// from the main ractor.
func TestRubyOtherRactors(t *testing.T) {
	const vmp, vm, ec, stack, iseq, body, label, pathv = 0x100, 0x200, 0x400, 0x10000, 0x500, 0x600, 0x700, 0x800
	const r1, r2, th1, th2 = 0x2000, 0x3000, 0x5000, 0x6000 // list head at +0x100, VM list node at +0x200
	l := rubyRow
	m := fakeMem{}
	m.u64(vmp, vm)
	m.u64(vm+l.vmMainThread, th1)
	m.u64(vm+l.vmRactorSet, r1+0x200)
	m.u64(r1+0x200, r2+0x200)
	m.u64(r2+0x200, vm+l.vmRactorSet)
	for _, c := range [][2]uint64{{r1, th1}, {r2, th2}} {
		m.u64(c[0]+0x100, c[1])
		m.u64(c[0]+0x100+l.thRactor, 0)
		m.u64(c[1], c[0]+0x100)
		m.u64(c[1]+l.thVM, vm)
		m.u64(c[1]+l.thRactor, c[0])
		m.u64(c[1]+l.thEC, ec)
	}
	size := uint64(1024)
	cfp := uint64(stack) + size*8 - l.cfpSize
	m.u64(ec+l.ecVMStack, stack)
	m.u64(ec+l.ecVMStackSize, size)
	m.u64(ec+l.ecCFP, cfp)
	m.u64(cfp+l.cfpIseq, iseq)
	m.u64(iseq, l.tImemo|l.imemoIseq<<l.fieldUShift)
	m.u64(iseq+l.iseqBody, body)
	m.u64(body+l.bodyLabel, label)
	m.u64(body+l.bodyPathobj, pathv)
	rubyString(m, label, "work")
	rubyString(m, pathv, "/app/w.rb")
	r, err := newRubyWalker(m, vmp, "3.4.7")
	if err != nil {
		t.Fatal(err)
	}
	fr := []string{"work (w.rb)"}
	st, err := r.Stacks()
	if err != nil || !reflect.DeepEqual(st, []PyStack{{Thread: th1, Frames: fr}, {Thread: th2, Frames: fr}}) {
		t.Fatalf("%+v %v", st, err)
	}
	m.u64(th2+l.thRactor, r1) // a thread that does not name its ractor is not read
	if st, _ := r.Stacks(); len(st) != 1 {
		t.Fatalf("%+v", st)
	}
}

func phpString(m fakeMem, at uint64, s string) {
	m.u32(at+phpStrInfo, phpTypeString)
	m.u64(at+phpStrLen, uint64(len(s)))
	m.put(at+phpStrVal, []byte(s))
}

func TestPHPWalker(t *testing.T) {
	const eg, ex1, ex2, fn1, fn2, n1, f1, ce, cn = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000
	l := phpTables["8.5"]
	m := fakeMem{}
	m.put(eg+phpZvalType, []byte{phpIsNull})
	m.put(eg+phpErrorZval+phpZvalType, []byte{phpIsError})
	m.u64(eg+l.curExec-8, phpStackPage)
	m.u64(eg+l.curExec, ex1)
	m.u64(ex1+phpExecFunc, fn1)
	m.u64(ex1+phpExecPrev, ex2)
	m.u64(ex2+phpExecFunc, fn2)
	m.u64(ex2+phpExecPrev, 0)
	m.put(fn1, []byte{phpUser})
	m.u64(fn1+phpFuncName, n1)
	m.u64(fn1+phpFuncScope, ce)
	m.u64(fn1+l.opFilename, f1)
	m.u64(ce+phpCeName, cn)
	phpString(m, n1, "run")
	phpString(m, cn, "App")
	phpString(m, f1, "/srv/a.php")
	m.put(fn2, []byte{phpUser})
	m.u64(fn2+phpFuncName, 0)
	m.u64(fn2+phpFuncScope, 0)
	m.u64(fn2+l.opFilename, f1)
	p, err := newPHPWalker(m, eg, "8.5")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.selfCheck(); err != nil {
		t.Fatal(err)
	}
	st, err := p.Stacks()
	if err != nil || !reflect.DeepEqual(st[0].Frames, []string{"App::run (a.php)", "<main> (a.php)"}) {
		t.Fatalf("%+v %v", st, err)
	}
	p.resetNames()
	m.u32(n1+phpStrInfo, 0) // torn string ends the stack, and no frame is invented
	if st, _ := p.Stacks(); len(st) != 0 {
		t.Fatalf("got %+v", st)
	}
	m.u64(eg+l.curExec-8, 7)
	if err := p.selfCheck(); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("err %v", err)
	}
	if _, err := newPHPWalker(m, eg, ""); err == nil {
		t.Fatal("an unknown version must be refused")
	}
	if phpVersion([]byte("xx\x00X-Powered-By: PHP/8.4.12\x00")) != "8.4" {
		t.Fatal("version scan")
	}
}

func nodeLookup(over map[string]int64) v8Lookup {
	vals := map[string]int64{
		"off_fp_context": -8, "off_fp_function": -16, "class_HeapObject__map__": 0, "class_Map__instance_type__": 12,
		"class_JSFunction__shared__": 24, "class_SharedFunctionInfo__name_or_scope_info__": 16,
		"class_SharedFunctionInfo__script__": 32, "class_Script__name__": 24, "class_String__length__": 12,
		"class_SeqOneByteString__chars__": 16, "class_ConsString__first__": 16, "class_ConsString__second__": 24,
		"class_ThinString__actual__": 16, "FirstJSFunctionType": 2000, "LastJSFunctionType": 2010, "FirstNonstringType": 128,
		"type_ScopeInfo__SCOPE_INFO_TYPE": 300, "type_Script__SCRIPT_TYPE": 301, "StringEncodingMask": 8, "OneByteStringTag": 8,
		"StringRepresentationMask": 7, "SeqStringTag": 0, "ConsStringTag": 1, "ThinStringTag": 5, "TaggedSize": 8, "HeapObjectTag": 1,
	}
	for k, v := range over {
		vals[k] = v
	}
	return func(n string) (int64, bool) { v, ok := vals[n]; return v, ok }
}

type nodeHeap struct {
	fakeMem
	next uint64
}

// obj allocates a tagged object of an instance type.
func (h *nodeHeap) obj(typ uint16) uint64 {
	mp := h.next
	h.next += 0x40
	h.u16(mp+12, typ)
	a := h.next
	h.next += 0x100
	h.u64(a, mp+1)
	return a + 1
}

func (h *nodeHeap) str(s string) uint64 {
	o := h.obj(8) // one-byte sequential
	h.u32(o-1+12, uint32(len(s)))
	h.put(o-1+16, []byte(s))
	return o
}

func TestNodeWalker(t *testing.T) {
	h := &nodeHeap{fakeMem{}, 0x100000}
	n, err := newNodeWalker(h, nodeLookup(nil), 0x10)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.selfCheck(); err != nil {
		t.Fatal(err)
	}
	script := h.obj(301)
	h.u64(script-1+24, h.str("/app/server.js"))
	jsFn := func(nameOrScope uint64) uint64 {
		sfi := h.obj(400)
		h.u64(sfi-1+16, nameOrScope)
		h.u64(sfi-1+32, script)
		fn := h.obj(2003)
		h.u64(fn-1+24, sfi)
		return fn
	}
	// Node 24+: uint32 flags, padding, position info first; two locals; function variable set.
	si := h.obj(300)
	h.u64(si-1+8, 1<<v8ScopeFnVarShift|2)
	h.u64(si-1+8+16, 2<<v8SmiShift)
	h.u64(si-1+8+40+4*8, h.str("handler"))
	// Node 22: Smi flags, inferred name.
	si22 := h.obj(300)
	h.u64(si22-1+8, (v8ScopeInferred|2)<<v8SmiShift)
	h.u64(si22-1+8+16, 0)
	h.u64(si22-1+8+24, h.str("inferred"))
	const fp1, fp2, fp3, fp4 = 0x1000, 0x2000, 0x3000, 0x4000
	frame := func(fp, ctx, fn, next uint64) {
		h.u64(fp-8, ctx)
		h.u64(fp-16, fn)
		h.u64(fp, next)
	}
	frame(fp1, 0x51, jsFn(h.str("direct")), fp2)
	frame(fp2, 0x2<<1, 0x51, fp3) // a Smi context: typed frame, not JS
	frame(fp3, 0x51, jsFn(si), fp4)
	frame(fp4, 0x51, jsFn(si22), 0)
	want := []string{"direct (server.js)", "handler (server.js)", "inferred (server.js)"}
	if got := n.StackFrom(0, 0, fp1); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	frame(fp1, 0x51, 0x12341, fp1) // an unreadable function and a chain that does not rise
	if got := n.StackFrom(0, 0, fp1); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if _, err := newNodeWalker(h, nodeLookup(map[string]int64{"TaggedSize": 4}), 0); err == nil {
		t.Fatal("pointer compression must be refused")
	}
	if _, err := newNodeWalker(h, func(string) (int64, bool) { return 0, false }, 0); err == nil || !strings.Contains(err.Error(), "lacks") {
		t.Fatalf("err %v", err)
	}
}

// jvmImage is a minimal gHotSpotVM* table and heap: an interpreted frame called by a compiled one.
func jvmImage(t *testing.T, drop string) (fakeMem, jvmSyms) {
	t.Helper()
	m := fakeMem{}
	s := jvmSyms{}
	next := uint64(0x10000)
	alloc := func(n uint64) uint64 { a := next; next += n; return a }
	sym := func(name string, v uint64) { a := alloc(8); m.u64(a, v); s[name] = a }
	cs := func(v string) uint64 { // padded to a 32-byte chunk, which cstr may read whole
		n := (uint64(len(v)) + 32) &^ 31
		next = (next + 31) &^ 31
		a := alloc(n)
		m.put(a, append([]byte(v), make([]byte, n-uint64(len(v)))...))
		return a
	}
	type fld struct {
		t, f   string
		static bool
		v      uint64
	}
	const thList, heaps = 0x90000, 0x90100
	flds := []fld{
		{"ThreadsSMRSupport", "_java_thread_list", true, thList}, {"ThreadsList", "_length", false, 0}, {"ThreadsList", "_threads", false, 8},
		{"JavaThread", "_anchor", false, 0x100}, {"JavaThread", "_thread_state", false, 0x50},
		{"JavaFrameAnchor", "_last_Java_sp", false, 0}, {"JavaFrameAnchor", "_last_Java_pc", false, 8}, {"JavaFrameAnchor", "_last_Java_fp", false, 16},
		{"CodeBlob", "_name", false, 8}, {"CodeBlob", "_frame_size", false, 16}, {"nmethod", "_method", false, 24},
		{"Method", "_constMethod", false, 8}, {"ConstMethod", "_constants", false, 8}, {"ConstMethod", "_name_index", false, 16},
		{"ConstantPool", "_pool_holder", false, 16}, {"Klass", "_name", false, 8}, {"Symbol", "_length", false, 0}, {"Symbol", "_body", false, 6},
		{"CodeCache", "_heaps", true, heaps}, {"CodeHeap", "_memory", false, 0}, {"CodeHeap", "_segmap", false, 32}, {"CodeHeap", "_log2_segment_size", false, 64},
		{"VirtualSpace", "_low", false, 0}, {"VirtualSpace", "_high", false, 8}, {"GrowableArrayBase", "_len", false, 0}, {"GrowableArray<int>", "_data", false, 8},
		// Inlining (JDK 17 names) and the JNI upcall.
		{"CodeBlob", "_code_begin", false, 32}, {"CompiledMethod", "_scopes_data_begin", false, 40},
		{"nmethod", "_scopes_pcs_offset", false, 48}, {"nmethod", "_metadata_offset", false, 52},
		{"PcDesc", "_pc_offset", false, 0}, {"PcDesc", "_scope_decode_offset", false, 4},
		{"StubRoutines", "_call_stub_return_address", true, 0x90200}, {"JavaCallWrapper", "_anchor", false, 0x20},
	}
	tys := map[string]string{
		"CodeBlob::_code_begin": "address", "CompiledMethod::_scopes_data_begin": "address", "nmethod::_scopes_pcs_offset": "int",
		"nmethod::_metadata_offset": "int", "PcDesc::_pc_offset": "int", "PcDesc::_scope_decode_offset": "int",
		"StubRoutines::_call_stub_return_address": "address",
	}
	m.u64(0x90200, 0x555000) // the call stub's return address
	tbl := alloc(48 * uint64(len(flds)+1))
	for i, f := range flds {
		e := tbl + uint64(i)*48
		if f.t+"::"+f.f == drop {
			f = fld{t: "Dropped", f: "x"}
		}
		m.u64(e, cs(f.t))
		m.u64(e+8, cs(f.f))
		m.u32(e+16, 0)
		m.u64(e+24, 0) // address
		m.u64(e+32, 0) // offset
		if f.static {
			m.u32(e+16, 1)
			m.u64(e+24, f.v)
		} else {
			m.u64(e+32, f.v)
		}
		m.u64(e+40, 0)
		if ty, ok := tys[f.t+"::"+f.f]; ok {
			m.u64(e+40, cs(ty))
		}
	}
	m.u64(tbl+uint64(len(flds))*48, 0)
	sym("gHotSpotVMStructs", tbl)
	sym("gHotSpotVMStructEntryTypeNameOffset", 0)
	sym("gHotSpotVMStructEntryFieldNameOffset", 8)
	sym("gHotSpotVMStructEntryIsStaticOffset", 16)
	sym("gHotSpotVMStructEntryAddressOffset", 24)
	sym("gHotSpotVMStructEntryOffsetOffset", 32)
	sym("gHotSpotVMStructEntryTypeStringOffset", 40)
	sym("gHotSpotVMStructEntryArrayStride", 48)
	types := alloc(64)
	m.u64(types, cs("ConstantPool"))
	m.u64(types+8, 32)
	m.u64(types+16, cs("HeapBlock"))
	m.u64(types+24, 16)
	m.u64(types+32, cs("PcDesc"))
	m.u64(types+40, 16)
	m.u64(types+48, 0)
	sym("gHotSpotVMTypes", types)
	sym("gHotSpotVMTypeEntryTypeNameOffset", 0)
	sym("gHotSpotVMTypeEntrySizeOffset", 8)
	sym("gHotSpotVMTypeEntryArrayStride", 16)
	ints := alloc(48)
	m.u64(ints, cs("_thread_in_Java"))
	m.u32(ints+8, 8)
	m.u64(ints+16, cs("frame::entry_frame_call_wrapper_offset"))
	m.u32(ints+24, uint32(0xfffffffa)) // -6
	m.u64(ints+32, 0)
	sym("gHotSpotVMIntConstants", ints)
	sym("gHotSpotVMIntConstantEntryNameOffset", 0)
	sym("gHotSpotVMIntConstantEntryValueOffset", 8)
	sym("gHotSpotVMIntConstantEntryArrayStride", 16)

	// One code heap of 16-byte segments; blobs at segment 1 (Interpreter) and 8 (nmethod).
	const heap, ga, data, low, seg = 0x91000, 0x92000, 0x93000, 0x100000, 0x180000
	m.u64(heaps, ga)
	m.u32(ga, 1)
	m.u64(ga+8, data)
	m.u64(data, heap)
	m.u64(heap, low)
	m.u64(heap+8, low+0x1000)
	m.u64(heap+32, seg)
	m.u32(heap+64, 4)
	for i := range uint64(32) {
		m.put(seg+i, []byte{0xff})
	}
	m.put(seg+1, []byte{0, 1, 2}) // segment 3 steps back to 1
	m.put(seg+8, []byte{0, 1})
	b := uint64(low + 1<<4 + 16)
	m.u64(b+8, cs("Interpreter"))
	m.u32(b+16, 0)
	return m, s
}

func TestJVMWalker(t *testing.T) {
	m, s := jvmImage(t, "")
	w, err := newJVMWalker(m, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.heaps) != 1 || w.inJava != 8 || w.poolSize != 32 || w.heapBlock != 16 {
		t.Fatalf("%+v", w)
	}
	if w.blobAt(0x100000+3<<4+4) == nil || !w.blobAt(0x100000+3<<4+4).interp {
		t.Fatal("segment map walk")
	}
	if w.blobAt(0x100000+20<<4) != nil || w.blobAt(0x900000) != nil {
		t.Fatal("a free segment or a foreign pc is no blob")
	}
	// A method named through its constant pool; a torn Method gives no name.
	const mt, cm, cp, k, ns, cs = 0xa0000, 0xa1000, 0xa2000, 0xa3000, 0xa4000, 0xa5000
	m.u64(mt+8, cm)
	m.u64(cm+8, cp)
	m.u16(cm+16, 5)
	m.u64(cp+16, k)
	m.u64(cp+32+5*8, ns)
	m.u64(k+8, cs)
	m.u16(ns, 3)
	m.put(ns+6, []byte("run"))
	m.u16(cs, 5)
	m.put(cs+6, []byte("a/b/C"))
	if n, ok := w.methodName(mt); !ok || n != "a.b.C.run" {
		t.Fatalf("%q %v", n, ok)
	}
	if _, ok := w.methodName(0xdead0); ok {
		t.Fatal("torn method")
	}
	// Interpreter leaf with a method, its sender a pc outside the code heaps.
	const fp = 0x700000
	m.u64(fp-jvmInterpMethod, mt)
	m.u64(fp-jvmInterpSenderSP, fp+0x40)
	m.u64(fp+8, 0x900000)
	m.u64(fp, fp+0x100)
	if got := w.StackFrom(0x100000+2<<4, fp-0x40, fp); !reflect.DeepEqual(got, []string{"a.b.C.run"}) {
		t.Fatalf("got %v", got)
	}
	// A thread outside Java code is read from its anchor; one in Java code is skipped.
	const tl, arr, th1, th2 = 0x90000, 0xb0000, 0xc0000, 0xd0000
	m.u64(tl, 0xb8000)
	m.u32(0xb8000, 2)
	m.u64(0xb8000+8, arr)
	m.u64(arr, th1)
	m.u64(arr+8, th2)
	for i, th := range []uint64{th1, th2} {
		st := uint32(8)
		if i == 0 {
			st = 10
		}
		m.u32(th+0x50, st)
		m.u64(th+0x100, fp-0x40)
		m.u64(th+0x108, 0x100000+2<<4)
		m.u64(th+0x110, fp)
	}
	if err := w.selfCheck(); err != nil {
		t.Fatal(err)
	}
	st, err := w.Stacks()
	if err != nil || !reflect.DeepEqual(st, []PyStack{{Thread: th1, Frames: []string{"a.b.C.run"}}}) {
		t.Fatalf("%+v %v", st, err)
	}
	// A compiled frame with one inlined method, called from native code through a JNI upcall
	// whose wrapper anchor leads back to the interpreted frame above.
	const nm, code, pcs, scopes, meta, mt2, cm2 = 0x100090, 0x100098, 0x100290, 0x100800, 0x100700, 0xa6000, 0xa7000
	m.u64(nm+8, 0xa8000)
	m.put(0xa8000, append([]byte("nmethod"), make([]byte, 25)...))
	m.u32(nm+16, 4)
	m.u64(nm+24, mt)
	m.u64(nm+32, code)
	m.u64(nm+40, scopes)
	m.u32(nm+48, pcs-nm)
	m.u32(nm+52, meta-nm)
	m.put(pcs, make([]byte, 1024))
	for i, r := range [][2]uint32{{0xffffffff, 0}, {4, 10}, {0x7fffffff, 0}} {
		m.u32(pcs+uint64(i)*16, r[0])
		m.u32(pcs+uint64(i)*16+4, r[1])
	}
	m.put(scopes, make([]byte, 48))
	m.put(scopes+10, []byte{21, 3, 1}) // UNSIGNED5: sender 20, metadata 2, bci 0
	m.put(scopes+20, []byte{1, 2, 1})  // sender none, metadata 1 (the nmethod's own method)
	m.u64(meta, mt)
	m.u64(meta+8, mt2)
	m.u64(mt2+8, cm2)
	m.u64(cm2+8, cp)
	m.u16(cm2+16, 6)
	m.u64(cp+32+6*8, 0xa9000)
	m.u16(0xa9000, 5)
	m.put(0xa9000+6, []byte("inner"))
	const csp = 0x600000
	m.u64(csp+0x18, 0x555000) // returns into the call stub
	m.u64(csp+0x10, csp+0x100)
	m.u64(csp+0x100-48, 0x680000) // JavaCallWrapper at entry fp - 6 words
	m.u64(0x680020, fp-0x40)
	m.u64(0x680028, 0x100000+2<<4)
	m.u64(0x680030, fp)
	want := []string{"a.b.C.inner", "a.b.C.run", "a.b.C.run"}
	if got := w.StackFrom(code+4, csp, 0); !reflect.DeepEqual(got, want) {
		t.Fatalf("inlined and upcall: got %v", got)
	}
	m.put(scopes+20, []byte{1, 3, 1}) // outermost is not the nmethod's method: outer name only
	w.resetNames()
	if got := w.StackFrom(code+4, csp, 0); !reflect.DeepEqual(got, want[1:]) {
		t.Fatalf("bad scopes: got %v", got)
	}
	m2, s2 := jvmImage(t, "ThreadsSMRSupport::_java_thread_list")
	if _, err := newJVMWalker(m2, s2); err == nil || !strings.Contains(err.Error(), "_java_thread_list") {
		t.Fatalf("err %v", err)
	}
	delete(s2, "gHotSpotVMStructs")
	if _, err := newJVMWalker(m2, s2); err == nil {
		t.Fatal("a missing export must be refused")
	}
}

func TestJVMReadIntBothEncodings(t *testing.T) {
	for _, c := range []struct {
		b []byte
		x uint32
	}{{[]byte{236, 1}, 0}, {[]byte{237, 2}, 1}} {
		pos := 0
		if v, ok := jvmReadInt(c.b, &pos, c.x); !ok || v != 300 || pos != 2 {
			t.Fatalf("x=%d: %d %v pos %d", c.x, v, ok, pos)
		}
	}
	pos := 0
	if _, ok := jvmReadInt([]byte{0}, &pos, 1); ok {
		t.Fatal("UNSIGNED5 never has a zero byte")
	}
}
