package ebpf

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Unwind rules of one table row: how to find the canonical frame address (CFA), the caller's
// frame pointer (rbp, x29: "RBP" below) and the return address at PCs from Row.PC up to the next
// row. RAOff 0 means the architecture's default: at CFA-8 on x86-64, still in x30 on arm64.
const (
	cfaNone        = 0 // no unwind info here: the BPF side falls back to frame pointers
	cfaRSP         = 1 // CFA = rsp + CFAOff
	cfaRBP         = 2 // CFA = rbp + CFAOff
	cfaUnsupported = 3 // an expression or another register: frame pointers
	cfaEnd         = 4 // the return address is undefined: outermost frame (_start, clone)

	rbpSame   = 0
	rbpOffset = 1 // caller rbp saved at CFA + RBPOff

)

// archRegs are the DWARF numbers of an architecture's stack and frame pointer.
type archRegs struct {
	sp, fp uint64
	lrRA   bool // the return address starts in a register (arm64), so its save slot matters
}

var (
	archX86   = archRegs{sp: 7, fp: 6}
	archARM64 = archRegs{sp: 31, fp: 29, lrRA: true}
)

// UnwindRow is one row of a binary's unwind table; PC is a link-time virtual address.
type UnwindRow struct {
	PC      uint64
	CFAReg  uint8
	CFAOff  int32
	RBPRule uint8
	RBPOff  int32
	RAOff   int32
}

func (r UnwindRow) sameRule(o UnwindRow) bool {
	return r.CFAReg == o.CFAReg && r.CFAOff == o.CFAOff && r.RBPRule == o.RBPRule && r.RBPOff == o.RBPOff && r.RAOff == o.RAOff
}

var errCFI = errors.New("malformed call frame information")

type reader struct {
	b   []byte
	off int
	err bool
}

func (r *reader) u8() uint8 {
	if r.off >= len(r.b) {
		r.err = true
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) n(k int) []byte {
	if k < 0 || r.off+k > len(r.b) {
		r.err = true
		r.off = len(r.b)
		return make([]byte, max(k, 0))
	}
	v := r.b[r.off : r.off+k]
	r.off += k
	return v
}

func (r *reader) u16() uint16 { return binary.LittleEndian.Uint16(r.n(2)) }
func (r *reader) u32() uint32 { return binary.LittleEndian.Uint32(r.n(4)) }
func (r *reader) u64() uint64 { return binary.LittleEndian.Uint64(r.n(8)) }

func (r *reader) uleb() uint64 {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b := r.u8()
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 || r.err {
			return v
		}
	}
	r.err = true
	return v
}

func (r *reader) sleb() int64 {
	var v int64
	var shift uint
	var b uint8
	for shift < 64 {
		b = r.u8()
		v |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 || r.err {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		v |= -1 << shift
	}
	return v
}

func (r *reader) cstr() string {
	start := r.off
	for r.off < len(r.b) && r.b[r.off] != 0 {
		r.off++
	}
	s := string(r.b[start:r.off])
	r.u8()
	return s
}

// ptr reads a DW_EH_PE-encoded pointer; base is the address of the field in memory (pcrel).
func (r *reader) ptr(enc uint8, base uint64) uint64 {
	if enc == 0xff { // omit
		return 0
	}
	var v uint64
	switch enc & 0x0f {
	case 0x00, 0x04:
		v = r.u64()
	case 0x01:
		v = r.uleb()
	case 0x02:
		v = uint64(r.u16())
	case 0x03:
		v = uint64(r.u32())
	case 0x09:
		v = uint64(r.sleb())
	case 0x0a:
		v = uint64(int64(int16(r.u16())))
	case 0x0b:
		v = uint64(int64(int32(r.u32())))
	case 0x0c:
		v = r.u64()
	default:
		r.err = true
	}
	if enc&0x70 == 0x10 { // pcrel; datarel/textrel/funcrel do not occur in x86-64 .eh_frame
		v += base
	}
	return v
}

type cie struct {
	codeAlign uint64
	dataAlign int64
	raReg     uint64
	fdeEnc    uint8
	aug       bool
	initial   []byte
}

// state is the CFA rule and the rbp / return-address rules at one PC.
type state struct {
	cfaReg  uint64
	cfaOff  int64
	cfaExpr bool
	rbp     uint8
	rbpOff  int64
	raUndef bool
	raOff   int64 // arm64: where the return address was saved, 0 while in x30
	arch    archRegs
}

func (s state) row(pc uint64) UnwindRow {
	r := UnwindRow{PC: pc, RBPRule: s.rbp, RBPOff: int32(s.rbpOff), RAOff: int32(s.raOff)}
	switch {
	case s.raUndef:
		r.CFAReg = cfaEnd
	case s.cfaExpr || s.cfaOff < -32768 || s.cfaOff > 32767 || s.rbpOff < -32768 || s.rbpOff > 32767 || s.raOff < -32768 || s.raOff > 32767:
		r.CFAReg = cfaUnsupported
	case s.cfaReg == s.arch.sp:
		r.CFAReg, r.CFAOff = cfaRSP, int32(s.cfaOff)
	case s.cfaReg == s.arch.fp:
		r.CFAReg, r.CFAOff = cfaRBP, int32(s.cfaOff)
	default:
		r.CFAReg = cfaUnsupported
	}
	if r.CFAReg == cfaUnsupported {
		r.RBPRule, r.RBPOff, r.RAOff = rbpSame, 0, 0
	}
	return r
}

// run executes CFA instructions from loc, appending a row each time the location advances.
func run(insns []byte, c *cie, loc uint64, st *state, initial *state, rows *[]UnwindRow) uint64 {
	r := &reader{b: insns}
	var stack []state
	emit := func(next uint64) {
		*rows = append(*rows, st.row(loc))
		loc = next
	}
	fp := st.arch.fp
	setReg := func(reg uint64, rule uint8, off int64) {
		switch reg {
		case fp:
			st.rbp, st.rbpOff = rule, off
		case c.raReg:
			st.raUndef = false
			if st.arch.lrRA {
				st.raOff = off
			}
		}
	}
	for r.off < len(r.b) && !r.err {
		op := r.u8()
		switch op & 0xc0 {
		case 0x40:
			emit(loc + uint64(op&0x3f)*c.codeAlign)
			continue
		case 0x80:
			setReg(uint64(op&0x3f), rbpOffset, int64(r.uleb())*c.dataAlign)
			continue
		case 0xc0:
			reg := uint64(op & 0x3f)
			if reg == fp {
				st.rbp, st.rbpOff = initial.rbp, initial.rbpOff
			} else if reg == c.raReg {
				st.raOff = initial.raOff
			}
			continue
		}
		switch op {
		case 0x00: // nop
		case 0x01: // set_loc
			emit(r.ptr(c.fdeEnc&0x0f, 0))
		case 0x02:
			emit(loc + uint64(r.u8())*c.codeAlign)
		case 0x03:
			emit(loc + uint64(r.u16())*c.codeAlign)
		case 0x04:
			emit(loc + uint64(r.u32())*c.codeAlign)
		case 0x05: // offset_extended
			reg := r.uleb()
			setReg(reg, rbpOffset, int64(r.uleb())*c.dataAlign)
		case 0x06, 0x08: // restore_extended, same_value
			if reg := r.uleb(); reg == fp {
				st.rbp, st.rbpOff = rbpSame, 0
			} else if reg == c.raReg {
				st.raOff = 0
			}
		case 0x07: // undefined
			if r.uleb() == c.raReg {
				st.raUndef = true
			}
		case 0x09: // register
			reg := r.uleb()
			r.uleb()
			if reg == fp {
				st.cfaExpr = true // rbp moved to another register: not expressible, use frame pointers
			}
		case 0x0a:
			stack = append(stack, *st)
		case 0x0b:
			if n := len(stack); n > 0 {
				*st, stack = stack[n-1], stack[:n-1]
			}
		case 0x0c: // def_cfa
			st.cfaReg, st.cfaOff, st.cfaExpr = r.uleb(), int64(r.uleb()), false
		case 0x0d:
			st.cfaReg, st.cfaExpr = r.uleb(), false
		case 0x0e:
			st.cfaOff = int64(r.uleb())
		case 0x0f: // def_cfa_expression
			r.n(int(r.uleb()))
			st.cfaExpr = true
		case 0x10, 0x16: // expression, val_expression
			reg := r.uleb()
			r.n(int(r.uleb()))
			if reg == fp {
				st.cfaExpr = true
			}
		case 0x11: // offset_extended_sf
			reg := r.uleb()
			setReg(reg, rbpOffset, r.sleb()*c.dataAlign)
		case 0x12: // def_cfa_sf
			st.cfaReg, st.cfaOff, st.cfaExpr = r.uleb(), r.sleb()*c.dataAlign, false
		case 0x13:
			st.cfaOff = r.sleb() * c.dataAlign
		case 0x14, 0x15: // val_offset(_sf): the register's value is CFA+off, not saved there
			reg := r.uleb()
			if op == 0x14 {
				r.uleb()
			} else {
				r.sleb()
			}
			if reg == fp {
				st.cfaExpr = true
			}
		case 0x2d: // AARCH64_negate_ra_state: pointer authentication, masked by the BPF walker
		case 0x2e: // GNU_args_size
			r.uleb()
		case 0x2f: // GNU_negative_offset_extended
			reg := r.uleb()
			setReg(reg, rbpOffset, -int64(r.uleb())*c.dataAlign)
		default:
			r.err = true
		}
	}
	return loc
}

// parseCFI turns a .eh_frame (ehFrame) or .debug_frame section into rows sorted by PC. addr is the
// section's virtual address (for pc-relative pointers in .eh_frame).
func parseCFI(b []byte, addr uint64, ehFrame bool, arch archRegs) ([]UnwindRow, error) {
	cies := map[int]*cie{}
	var rows []UnwindRow
	type rng struct{ lo, hi uint64 }
	var ranges []rng
	for off := 0; off+4 <= len(b); {
		r := &reader{b: b, off: off}
		length := uint64(r.u32())
		if length == 0 {
			if ehFrame {
				break
			}
			off += 4
			continue
		}
		wide := length == 0xffffffff
		if wide {
			length = r.u64()
		}
		bodyStart := r.off
		end := bodyStart + int(length)
		if length > uint64(len(b)) || end > len(b) || end < bodyStart {
			return nil, errCFI
		}
		idPos := r.off
		var id uint64
		if wide {
			id = r.u64()
		} else {
			id = uint64(r.u32())
		}
		isCIE := (ehFrame && id == 0) || (!ehFrame && (id == 0xffffffff || id == 0xffffffffffffffff))
		e := &reader{b: b[:end], off: r.off}
		if isCIE {
			c, err := parseCIE(e, ehFrame)
			if err != nil {
				return nil, err
			}
			cies[off] = c
		} else {
			cieOff := int(id)
			if ehFrame {
				cieOff = idPos - int(id)
			}
			c, ok := cies[cieOff]
			if !ok {
				var err error
				if c, err = cieAt(b, cieOff, ehFrame); err != nil {
					return nil, err
				}
				cies[cieOff] = c
			}
			enc := c.fdeEnc
			if !ehFrame {
				enc = 0x00
			}
			lo := e.ptr(enc, addr+uint64(e.off))
			n := e.ptr(enc&0x0f, 0)
			if c.aug {
				e.n(int(e.uleb()))
			}
			if e.err {
				return nil, errCFI
			}
			insns := e.b[e.off:end]
			init := state{rbp: rbpSame, arch: arch}
			run(c.initial, c, lo, &init, &init, &[]UnwindRow{})
			st := init
			last := run(insns, c, lo, &st, &init, &rows)
			rows = append(rows, st.row(last)) // the final state holds to the FDE's end
			ranges = append(ranges, rng{lo, lo + n})
		}
		off = end
	}
	// a gap after an FDE has no unwind info
	for _, g := range ranges {
		rows = append(rows, UnwindRow{PC: g.hi, CFAReg: cfaNone})
	}
	return compact(rows), nil
}

func cieAt(b []byte, off int, ehFrame bool) (*cie, error) {
	r := &reader{b: b, off: off}
	length := uint64(r.u32())
	wide := length == 0xffffffff
	if wide {
		length = r.u64()
	}
	end := r.off + int(length)
	if end > len(b) || r.err {
		return nil, errCFI
	}
	if wide {
		r.u64()
	} else {
		r.u32()
	}
	return parseCIE(&reader{b: b[:end], off: r.off}, ehFrame)
}

func parseCIE(e *reader, ehFrame bool) (*cie, error) {
	c := &cie{fdeEnc: 0x00}
	version := e.u8()
	aug := e.cstr()
	if !ehFrame && version >= 4 {
		e.u8() // address_size
		e.u8() // segment_selector_size
	}
	c.codeAlign = e.uleb()
	c.dataAlign = e.sleb()
	if version == 1 {
		c.raReg = uint64(e.u8())
	} else {
		c.raReg = e.uleb()
	}
	if len(aug) > 0 && aug[0] == 'z' {
		c.aug = true
		n := int(e.uleb())
		a := &reader{b: e.n(n)}
		for _, ch := range aug[1:] {
			switch ch {
			case 'R':
				c.fdeEnc = a.u8()
			case 'L':
				a.u8()
			case 'P':
				pe := a.u8()
				a.ptr(pe&0x7f, 0)
			}
		}
	} else if aug != "" {
		return nil, fmt.Errorf("unsupported CIE augmentation %q", aug)
	}
	if e.err {
		return nil, errCFI
	}
	c.initial = e.b[e.off:]
	return c, nil
}

// compact sorts rows by PC, lets an FDE's own rows win over a gap marker at the same PC and
// merges neighbours with the same rule.
func compact(rows []UnwindRow) []UnwindRow {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PC != rows[j].PC {
			return rows[i].PC < rows[j].PC
		}
		return rows[i].CFAReg == cfaNone && rows[j].CFAReg != cfaNone
	})
	out := rows[:0]
	for i, r := range rows {
		if i+1 < len(rows) && rows[i+1].PC == r.PC {
			continue // the later row at the same PC wins
		}
		if n := len(out); n > 0 && out[n-1].sameRule(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// TableForELF reads the unwind rows of an x86-64 or arm64 ELF file (.eh_frame, else .debug_frame).
func TableForELF(f *elf.File) ([]UnwindRow, error) {
	var arch archRegs
	switch f.Machine {
	case elf.EM_X86_64:
		arch = archX86
	case elf.EM_AARCH64:
		arch = archARM64
	default:
		return nil, fmt.Errorf("unwind tables are built for x86-64 and arm64, not %s", f.Machine)
	}
	for _, name := range []string{".eh_frame", ".debug_frame"} {
		s := f.Section(name)
		if s == nil || s.Type == elf.SHT_NOBITS {
			continue
		}
		b, err := s.Data()
		if err != nil {
			return nil, err
		}
		return parseCFI(b, s.Addr, name == ".eh_frame", arch)
	}
	return nil, errors.New("no .eh_frame or .debug_frame")
}
