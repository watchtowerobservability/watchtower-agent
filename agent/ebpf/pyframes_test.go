package ebpf

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

// fakeMem is a sparse little-endian memory image.
type fakeMem map[uint64]byte

func (m fakeMem) ReadAt(a uint64, b []byte) error {
	for i := range b {
		v, ok := m[a+uint64(i)]
		if !ok {
			return errors.New("unmapped")
		}
		b[i] = v
	}
	return nil
}

func (m fakeMem) put(a uint64, b []byte) {
	for i, v := range b {
		m[a+uint64(i)] = v
	}
}

func (m fakeMem) u64(a, v uint64) { m.put(a, binary.LittleEndian.AppendUint64(nil, v)) }

func (m fakeMem) ascii(a uint64, s string) {
	m.put(a+16, []byte{0x60, 0, 0, 0})
	m.u64(a+8, uint64(len(s)))
	m.put(a+40, []byte(s))
}

func TestPyWalkerReadsAThreadByTheProcessOwnOffsets(t *testing.T) {
	m := fakeMem{}
	const rt, interp, ts, f1, f2, f3, code1, code2, typ, typName = 0x1000, 0x2000, 0x3000, 0x4000, 0x4100, 0x4200, 0x5000, 0x6000, 0x7000, 0x7100
	w := pyTables[13]
	table := map[uint64]uint64{w.interpHead: 0x800, w.interpNext: 8, w.threadsHead: 16, w.threadNext: 8, w.curFrame: 24, w.nativeTid: 32,
		w.framePrev: 0, w.frameExec: 8, w.frameOwner: 16, w.codeFilename: 16, w.codeQualname: 24, w.obType: 8, w.tpName: 24,
		w.uniState: 16, w.uniLen: 8, w.uniASCII: 40}
	for i := uint64(0); i < w.tableWords; i++ {
		m.u64(rt+8*i, table[i])
	}
	m.put(rt, []byte("xdebugpy"))
	m.u64(rt+8, 0x030d00f0)
	m.u64(rt+16, 0)
	m.u64(rt+0x800, interp)
	m.u64(interp+8, 0)
	m.u64(interp+16, ts)
	m.u64(ts+8, 0)
	m.u64(ts+24, f1)
	m.u64(ts+32, 77)
	m.u64(f1, f2) // leaf
	m.u64(f1+8, code1|1)
	m.put(f1+16, []byte{0})
	m.u64(f2, f3) // a C-stack shim frame: skipped
	m.u64(f2+8, 0)
	m.put(f2+16, []byte{3})
	m.u64(f3, 0)
	m.u64(f3+8, code2)
	m.put(f3+16, []byte{1})
	for _, c := range []uint64{code1, code2} {
		m.u64(c+8, typ)
	}
	m.u64(typ+24, typName)
	m.put(typName, []byte("code\x00"))
	m.u64(code1+16, 0x8000)
	m.u64(code1+24, 0x8100)
	m.u64(code2+16, 0x8000)
	m.u64(code2+24, 0x8200)
	m.ascii(0x8000, "/srv/app/a.py")
	m.ascii(0x8100, "Foo.bar")
	m.ascii(0x8200, "main;x")
	p, err := newPyWalker(m, rt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Stacks()
	if err != nil {
		t.Fatal(err)
	}
	want := []PyStack{{Thread: 77, Frames: []string{"Foo.bar (a.py)", "main:x (a.py)"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	m.put(rt, []byte("notpython"))
	if _, err := newPyWalker(m, rt); err == nil {
		t.Fatal("a missing cookie must be refused")
	}
}

func TestPyStacksFoldToAProfile(t *testing.T) {
	f := newPyFolder()
	f.add(7, []string{"leaf (a.py)", "main (a.py)"})
	f.add(7, []string{"leaf (a.py)", "main (a.py)"})
	f.add(8, []string{"leaf (a.py)"})
	es := f.entries()
	if len(es) != 2 || len(f.names) != 2 {
		t.Fatalf("entries %+v names %v", es, f.names)
	}
	r := pyResolver{Resolver: nil, names: f.names}
	if got := r.User(7, 2).Name; got != "main (a.py)" {
		t.Fatalf("name %q", got)
	}
	if r.User(7, 99).Name != "" {
		t.Fatal("an unknown id has no name")
	}
}
