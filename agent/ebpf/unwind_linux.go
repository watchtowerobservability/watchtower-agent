//go:build linux

package ebpf

import (
	"github.com/cilium/ebpf"
)

const maxDwarfFrames = 64 // MAX_FRAMES in bpf/cpu_dwarf.bpf.c

// bpfRow mirrors `struct row` in bpf/cpu_dwarf.bpf.c (16 bytes).
type bpfRow struct {
	PC      uint64
	CFAReg  uint8
	RBPRule uint8
	CFAOff  int16
	RBPOff  int16
	RAOff   int16
}

// mapSink writes unwind tables into the maps of cpu_dwarf.
type mapSink struct{ procs, rows *ebpf.Map }

func (m mapSink) putRows(off uint32, rows []UnwindRow) error {
	keys := make([]uint32, len(rows))
	vals := make([]bpfRow, len(rows))
	for i, r := range rows {
		keys[i] = off + uint32(i)
		vals[i] = bpfRow{PC: r.PC, CFAReg: r.CFAReg, RBPRule: r.RBPRule, CFAOff: int16(r.CFAOff), RBPOff: int16(r.RBPOff), RAOff: int16(r.RAOff)}
	}
	if _, err := m.rows.BatchUpdate(keys, vals, nil); err == nil {
		return nil
	}
	for i := range keys { // kernels without batch ops on arrays
		if err := m.rows.Update(keys[i], vals[i], ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func (m mapSink) putProc(pid uint32, p *unwindProc) error {
	return m.procs.Update(pid, p, ebpf.UpdateAny)
}

func (m mapSink) delProc(pid uint32) error { return m.procs.Delete(pid) }
