package ebpf

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// rubyLayout holds byte offsets of the struct fields the walker uses, read from vm_core.h and
// include/ruby/internal/core/{rstring,rarray}.h of each maintained branch (LP64, non-debug).
type rubyLayout struct {
	vmRactorSet, vmMainThread, thVM, thRactor   uint64
	thEC                                        uint64
	ecVMStack, ecVMStackSize, ecCFP             uint64
	cfpIseq, cfpSize                            uint64
	iseqBody, bodyPathobj, bodyLabel            uint64
	strLen, strPtr, strEmbed, arrEmbed, arrHeap uint64
	fieldUShift, tMask, tString, tArray, tImemo uint64
	imemoIseq, noEmbedFlag                      uint64
}

// The branches differ in other fields, not in these; each keeps its own row so that a future
// branch is added by reading its headers, not by assuming.
var rubyTables = map[string]rubyLayout{
	"3.3": rubyRow, // security maintenance until 2027-03
	"3.4": rubyRow,
	"4.0": rubyRow,
}

var rubyRow = rubyLayout{
	vmRactorSet: 8, vmMainThread: 40, thVM: 32, thRactor: 24, thEC: 48,
	ecVMStack: 0, ecVMStackSize: 8, ecCFP: 16,
	cfpIseq: 16, cfpSize: 56,
	iseqBody: 16, bodyPathobj: 64, bodyLabel: 80,
	strLen: 16, strPtr: 24, strEmbed: 24, arrEmbed: 16, arrHeap: 32,
	fieldUShift: 12, tMask: 0x1f, tString: 0x05, tArray: 0x07, tImemo: 0x1a,
	imemoIseq: 7, noEmbedFlag: 1 << 13,
}

// rubyWalker reads Ruby-level stacks of every ractor's threads. Each thread's control frames run
// from ec->cfp up to the end of its VM stack.
type rubyWalker struct {
	m     rmem
	vmPtr uint64 // address of ruby_current_vm_ptr
	l     rubyLayout
	names map[uint64]string
}

// newRubyWalker takes the target's ruby_version string, e.g. "3.4.7".
func newRubyWalker(mem memReader, vmPtr uint64, version string) (*rubyWalker, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unreadable Ruby version %q", version)
	}
	l, ok := rubyTables[parts[0]+"."+parts[1]]
	if !ok {
		return nil, fmt.Errorf("Ruby %s has no offset table", version)
	}
	return &rubyWalker{m: rmem{mem}, vmPtr: vmPtr, l: l, names: map[uint64]string{}}, nil
}

func (r *rubyWalker) mainThread() (vm, th uint64, err error) {
	if vm, err = r.m.u64(r.vmPtr); err != nil {
		return 0, 0, err
	}
	if vm == 0 {
		return 0, 0, errNotReady
	}
	th, err = r.m.u64(vm + r.l.vmMainThread)
	return vm, th, err
}

// selfCheck: the main thread points back at the VM, and the control frames sit a whole number of
// frames from the end of the VM stack (a debug build's larger frame fails that).
func (r *rubyWalker) selfCheck() error {
	vm, th, err := r.mainThread()
	if err != nil {
		return err
	}
	if th == 0 {
		return errNotReady
	}
	back, err := r.m.u64(th + r.l.thVM)
	if err != nil {
		return err
	}
	if back != vm {
		return errors.New("offset table mismatch: main thread does not point at the VM")
	}
	ec, err := r.m.u64(th + r.l.thEC)
	if err != nil {
		return err
	}
	cfp, end, err := r.frames(ec)
	if err != nil {
		return err
	}
	if (end-cfp)%r.l.cfpSize != 0 {
		return errors.New("offset table mismatch: control frames do not fit the VM stack (VM_DEBUG_BP_CHECK build?)")
	}
	if len(r.thread(ec)) == 0 {
		return errNotReady
	}
	return nil
}

func (r *rubyWalker) frames(ec uint64) (cfp, end uint64, err error) {
	base, err := r.m.u64(ec + r.l.ecVMStack)
	if err != nil {
		return 0, 0, err
	}
	size, err := r.m.u64(ec + r.l.ecVMStackSize)
	if err != nil {
		return 0, 0, err
	}
	if cfp, err = r.m.u64(ec + r.l.ecCFP); err != nil {
		return 0, 0, err
	}
	end = base + size*8
	if base == 0 || size == 0 || size > rtStackSpan/8 || cfp < base || cfp > end {
		return 0, 0, errors.New("implausible VM stack")
	}
	return cfp, end, nil
}

// str reads a T_STRING, truncated to the name limit.
func (r *rubyWalker) str(v uint64) (string, error) {
	flags, err := r.m.u64(v)
	if err != nil {
		return "", err
	}
	if flags&r.l.tMask != r.l.tString {
		return "", errors.New("not a string")
	}
	n, err := r.m.u64(v + r.l.strLen)
	if err != nil {
		return "", err
	}
	if n > rtStackSpan {
		return "", errors.New("implausible string length")
	}
	at := v + r.l.strEmbed
	if flags&r.l.noEmbedFlag != 0 {
		if at, err = r.m.u64(v + r.l.strPtr); err != nil {
			return "", err
		}
	}
	b := make([]byte, min(n, rtMaxString))
	if err := r.m.ReadAt(at, b); err != nil {
		return "", err
	}
	return string(b), nil
}

// file reads an iseq's pathobj: a String, or an Array whose first element is the path.
func (r *rubyWalker) file(v uint64) (string, error) {
	flags, err := r.m.u64(v)
	if err != nil {
		return "", err
	}
	if flags&r.l.tMask == r.l.tString {
		return r.str(v)
	}
	if flags&r.l.tMask != r.l.tArray {
		return "", errors.New("pathobj is neither String nor Array")
	}
	at := v + r.l.arrEmbed
	if flags&r.l.noEmbedFlag == 0 { // RARRAY_EMBED_FLAG is FL_USER1, the bit noEmbedFlag names
		if at, err = r.m.u64(v + r.l.arrHeap); err != nil {
			return "", err
		}
	}
	first, err := r.m.u64(at)
	if err != nil {
		return "", err
	}
	return r.str(first)
}

// frameName is `label (file.rb)`; ok is false for C frames, ifuncs and anything torn.
func (r *rubyWalker) frameName(iseq uint64) (string, bool) {
	if n, ok := r.names[iseq]; ok {
		return n, true
	}
	flags, err := r.m.u64(iseq)
	if err != nil || flags&r.l.tMask != r.l.tImemo || flags>>r.l.fieldUShift&0xf != r.l.imemoIseq {
		return "", false
	}
	body, err := r.m.u64(iseq + r.l.iseqBody)
	if err != nil {
		return "", false
	}
	lv, e1 := r.m.u64(body + r.l.bodyLabel)
	pv, e2 := r.m.u64(body + r.l.bodyPathobj)
	if e1 != nil || e2 != nil {
		return "", false
	}
	label, e1 := r.str(lv)
	file, e2 := r.file(pv)
	if e1 != nil || e2 != nil || !printable(label) {
		return "", false
	}
	n := strings.ReplaceAll(label+" ("+path.Base(file)+")", ";", ":")
	r.names[iseq] = n
	return n, true
}

func (r *rubyWalker) thread(ec uint64) []string {
	cfp, end, err := r.frames(ec)
	if err != nil {
		return nil
	}
	var out []string
	for ; cfp < end && len(out) < rtMaxFrames; cfp += r.l.cfpSize {
		iseq, err := r.m.u64(cfp + r.l.cfpIseq)
		if err != nil {
			break
		}
		if iseq == 0 {
			continue // a C frame
		}
		if n, ok := r.frameName(iseq); ok {
			out = append(out, n)
		}
	}
	return out
}

// rtMaxRactors caps the ractors read per window.
const rtMaxRactors = 64

// Stacks walks the main ractor's circular thread list, then every other ractor's. A thread list
// goes through a head inside its ractor, and the VM's ractor list through a node inside each
// ractor. Neither offset is in a table: the main ractor's own list head and its node in the VM's
// list (it is inserted first, at boot) give both, and a thread counts only if it names its ractor.
func (r *rubyWalker) Stacks() ([]PyStack, error) {
	vm, main, err := r.mainThread()
	if err != nil {
		return nil, err
	}
	mainR, err := r.m.u64(main + r.l.thRactor)
	if err != nil {
		return nil, err
	}
	var out []PyStack
	left := rtMaxThreads
	head := r.ractorThreads(main, main, mainR, &left, &out)
	set := vm + r.l.vmRactorSet
	first, err := r.m.u64(set)
	if err != nil || head <= mainR || first <= mainR || first == set {
		return out, nil // one ractor, or a list that does not fit: the main ractor alone
	}
	headOff, nodeOff := head-mainR, first-mainR
	if headOff > 1<<14 || nodeOff > 1<<14 || headOff%8 != 0 || nodeOff%8 != 0 {
		return out, nil
	}
	n := first
	for range rtMaxRactors {
		if n, err = r.m.u64(n); err != nil || n == 0 || n == set || n == first {
			break // ccan_list_node.next sits at offset 0
		}
		ractor := n - nodeOff
		h := ractor + headOff
		if at, err := r.m.u64(h); err == nil && at != 0 && at != h {
			r.ractorThreads(at, h, ractor, &left, &out)
		}
	}
	return out, nil
}

// ractorThreads reads one ractor's threads around its circular list, from node at until stop,
// and returns the first node that is not a thread of the ractor: the list head.
func (r *rubyWalker) ractorThreads(at, stop, ractor uint64, left *int, out *[]PyStack) (head uint64) {
	for th := at; *left > 0; *left-- {
		if own, err := r.m.u64(th + r.l.thRactor); err == nil && own == ractor {
			if ec, err := r.m.u64(th + r.l.thEC); err == nil && ec != 0 {
				if fr := r.thread(ec); len(fr) > 0 {
					*out = append(*out, PyStack{Thread: th, Frames: fr})
				}
			}
		} else if head == 0 {
			head = th
		}
		var err error
		if th, err = r.m.u64(th); err != nil || th == 0 || th == stop {
			break // lt_node.next sits at offset 0
		}
	}
	return head
}

func (r *rubyWalker) resetNames() { r.names = map[uint64]string{} }
