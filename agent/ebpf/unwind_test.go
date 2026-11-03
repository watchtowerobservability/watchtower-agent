package ebpf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// ehFrame builds a gcc-style .eh_frame at addr: one zR CIE and one FDE for [lo, lo+n).
func ehFrame(addr, lo uint64, n uint32, insns []byte) []byte {
	cieBody := []byte{0, 0, 0, 0, 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 7, 8, 0x90, 1, 0, 0}
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(len(cieBody)))
	b = append(b, cieBody...)
	fdeStart := len(b)
	body := binary.LittleEndian.AppendUint32(nil, uint32(fdeStart+4)) // back to the CIE
	pcField := addr + uint64(fdeStart+4+4)
	body = binary.LittleEndian.AppendUint32(body, uint32(int32(int64(lo)-int64(pcField))))
	body = binary.LittleEndian.AppendUint32(body, n)
	body = append(append(body, 0), insns...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	return binary.LittleEndian.AppendUint32(append(b, body...), 0)
}

func TestParseCFIFramePointerPrologue(t *testing.T) {
	// push rbp; mov rbp,rsp; ...; pop rbp (cfa back to rsp+8)
	insns := []byte{0x41, 0x0e, 16, 0x86, 2, 0x43, 0x0d, 6, 0x4a, 0x0c, 7, 8}
	rows, err := parseCFI(ehFrame(0x5000, 0x1000, 0x20, insns), 0x5000, true, archX86)
	if err != nil {
		t.Fatal(err)
	}
	want := []UnwindRow{
		{PC: 0x1000, CFAReg: cfaRSP, CFAOff: 8},
		{PC: 0x1001, CFAReg: cfaRSP, CFAOff: 16, RBPRule: rbpOffset, RBPOff: -16},
		{PC: 0x1004, CFAReg: cfaRBP, CFAOff: 16, RBPRule: rbpOffset, RBPOff: -16},
		{PC: 0x100e, CFAReg: cfaRSP, CFAOff: 8, RBPRule: rbpOffset, RBPOff: -16},
		{PC: 0x1020, CFAReg: cfaNone},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows\n got %+v\nwant %+v", rows, want)
	}
}

func TestParseCFIExpressionAndRememberState(t *testing.T) {
	// remember; def_cfa_expression (PLT style); restore -> back to rsp+8
	insns := []byte{0x0a, 0x0f, 2, 0x77, 8, 0x42, 0x0b}
	rows, err := parseCFI(ehFrame(0, 0x2000, 8, insns), 0, true, archX86)
	if err != nil {
		t.Fatal(err)
	}
	want := []UnwindRow{{PC: 0x2000, CFAReg: cfaUnsupported}, {PC: 0x2002, CFAReg: cfaRSP, CFAOff: 8}, {PC: 0x2008}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got %+v", rows)
	}
	if _, err := parseCFI([]byte{0xff, 0, 0, 0, 1}, 0, true, archX86); err == nil {
		t.Fatal("a truncated entry must fail")
	}
}

func TestParseCFIARM64ReturnAddressRule(t *testing.T) {
	// data align -8, return register 30: stp x29,x30,[sp,#-16]!; mov x29,sp; later restore x30
	cieBody := []byte{0, 0, 0, 0, 1, 'z', 'R', 0, 4, 0x78, 30, 1, 0x1b, 0x0c, 31, 0, 0, 0}
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, uint32(len(cieBody)))
	b = append(b, cieBody...)
	body := binary.LittleEndian.AppendUint32(nil, uint32(len(b)+4))
	body = binary.LittleEndian.AppendUint32(body, uint32(int32(0x1000-int64(len(b)+8))))
	body = binary.LittleEndian.AppendUint32(body, 0x40)
	// advance 1 instruction; cfa=sp+16; x29 at cfa-16; x30 at cfa-8; advance 1; cfa=x29+16; advance 2; restore x30; negate_ra_state
	body = append(body, 0, 0x41, 0x0e, 16, 0x80|29, 2, 0x80|30, 1, 0x41, 0x0c, 29, 16, 0x42, 0xc0|30, 0x2d)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	b = binary.LittleEndian.AppendUint32(append(b, body...), 0)
	rows, err := parseCFI(b, 0, true, archARM64)
	if err != nil {
		t.Fatal(err)
	}
	want := []UnwindRow{
		{PC: 0x1000, CFAReg: cfaRSP},
		{PC: 0x1004, CFAReg: cfaRSP, CFAOff: 16, RBPRule: rbpOffset, RBPOff: -16, RAOff: -8},
		{PC: 0x1008, CFAReg: cfaRBP, CFAOff: 16, RBPRule: rbpOffset, RBPOff: -16, RAOff: -8},
		{PC: 0x1010, CFAReg: cfaRBP, CFAOff: 16, RBPRule: rbpOffset, RBPOff: -16},
		{PC: 0x1040},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows\n got %+v\nwant %+v", rows, want)
	}
}

type fakeSink struct {
	rows  map[uint32]UnwindRow
	procs map[uint32]unwindProc
}

func (f *fakeSink) putRows(off uint32, rows []UnwindRow) error {
	for i, r := range rows {
		f.rows[off+uint32(i)] = r
	}
	return nil
}
func (f *fakeSink) putProc(pid uint32, p *unwindProc) error { f.procs[pid] = *p; return nil }
func (f *fakeSink) delProc(pid uint32) error                { delete(f.procs, pid); return nil }

func TestUnwindCacheBiasesPCsAndEvicts(t *testing.T) {
	proc := t.TempDir()
	for _, pid := range []string{"10", "11"} {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		maps := "55d000400000-55d000500000 r-xp 00001000 08:01 1 /usr/bin/app\n" +
			"7f0000000000-7f0000001000 rwxp 00000000 00:00 0 \n"
		if err := os.WriteFile(filepath.Join(proc, pid, "maps"), []byte(maps), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sink := &fakeSink{rows: map[uint32]UnwindRow{}, procs: map[uint32]unwindProc{}}
	c := newUnwindCache(sink)
	c.proc = proc
	reads := 0
	c.tableOf = func(string, uint64) ([]UnwindRow, uint64, error) {
		reads++
		return []UnwindRow{{PC: 0x1000, CFAReg: cfaRSP, CFAOff: 8}, {PC: 0x1100}}, 0x0, nil
	}
	c.Observe([]uint32{10, 11, 99})
	if reads != 2 || len(sink.rows) != 4 { // no build id: one table per root path
		t.Fatalf("reads %d rows %d", reads, len(sink.rows))
	}
	p := sink.procs[10]
	if p.N != 1 || p.Maps[0].Bias != 0x55d000400000-0x1000 || p.Maps[0].Len != 2 {
		t.Fatalf("proc %+v", p.Maps[0])
	}
	if _, ok := sink.procs[99]; ok {
		t.Fatal("a pid without maps gets no table")
	}
	c.procs = map[uint32]uint64{}
	for i := uint32(0); i < maxUnwindProcs; i++ {
		c.procs[1000+i] = 0
	}
	c.Observe([]uint32{10})
	if len(c.procs) != maxUnwindProcs {
		t.Fatalf("eviction keeps %d procs", len(c.procs))
	}
}

func TestUnwindRowsFreeList(t *testing.T) {
	c := newUnwindCache(&fakeSink{rows: map[uint32]UnwindRow{}, procs: map[uint32]unwindProc{}})
	a, _ := c.alloc(10)
	b, _ := c.alloc(5)
	d, _ := c.alloc(7)
	if a != 0 || b != 10 || d != 15 || c.next != 22 {
		t.Fatalf("bump: %d %d %d next %d", a, b, d, c.next)
	}
	c.release(a, 10)
	if got, _ := c.alloc(4); got != 0 {
		t.Fatalf("first fit reuses freed rows, got %d", got)
	}
	c.release(10, 5) // merges with the 6 rows left at 4
	if !reflect.DeepEqual(c.free, []rowExtent{{4, 11}}) {
		t.Fatalf("free %+v", c.free)
	}
	c.release(15, 7) // ends at next: next shrinks, the merged range goes with it
	if c.next != 4 || len(c.free) != 0 {
		t.Fatalf("next %d free %+v", c.next, c.free)
	}
	if _, ok := c.alloc(maxUnwindRows); ok {
		t.Fatal("more rows than the space must fail")
	}
}

func TestUnwindCacheFreesTablesOfEvictedProcesses(t *testing.T) {
	proc := t.TempDir()
	for _, pid := range []string{"10", "11"} {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		// Four mappings at different offsets: four tables of the largest size fill the space.
		maps := "55d000400000-55d000500000 r-xp 00001000 08:01 1 /usr/bin/app\n" +
			"55d000500000-55d000600000 r-xp 00101000 08:01 1 /usr/bin/app\n" +
			"55d000600000-55d000700000 r-xp 00201000 08:01 1 /usr/bin/app\n" +
			"55d000700000-55d000800000 r-xp 00301000 08:01 1 /usr/bin/app\n"
		if err := os.WriteFile(filepath.Join(proc, pid, "maps"), []byte(maps), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sink := &fakeSink{rows: map[uint32]UnwindRow{}, procs: map[uint32]unwindProc{}}
	c := newUnwindCache(sink)
	c.proc = proc
	c.tableOf = func(string, uint64) ([]UnwindRow, uint64, error) {
		return make([]UnwindRow, maxBinaryRows), 0, nil // one process fills every row
	}
	c.Observe([]uint32{10})
	c.Observe([]uint32{11}) // does not fit: 10 is older and goes at the next window
	if _, ok := sink.procs[11]; ok || !c.full {
		t.Fatalf("11 cannot fit yet: %v", c.full)
	}
	c.Observe([]uint32{11})
	if _, ok := sink.procs[11]; !ok {
		t.Fatal("11 gets the rows 10 freed")
	}
	if _, ok := sink.procs[10]; ok || len(c.uses) != 1 {
		t.Fatalf("10 evicted: uses %v", c.uses)
	}
}
