package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Limits of every walk of a target's memory: the target keeps running and is never stopped or
// written to, so any value can be stale or torn. A bad value ends that stack, nothing more.
const (
	rtMaxFrames  = 128
	rtMaxThreads = 512
	rtMaxString  = 512
	rtStackSpan  = 1 << 26 // a frame chain longer than this is not a stack
)

// Read caps: all readers' reads per sampling tick, for walks and again for register
// samples. Each CPU guard cut halves them; the floor keeps a trickle of samples alive.
const (
	rtTickReads    = 2048
	rtMinTickReads = 64
)

func rtReadCap(cuts int) int { return max(rtTickReads>>max(cuts, 0), rtMinTickReads) }

// errNotReady means the runtime is still starting up: try the attach again later.
var errNotReady = errors.New("runtime not initialised yet")

// stackWalker reads the stacks of one process's runtime.
type stackWalker interface {
	// selfCheck runs at attach. It proves the table fits this build, or the attach is refused.
	selfCheck() error
	// Stacks reads every thread that can be read without its registers.
	Stacks() ([]PyStack, error)
	// resetNames drops cached names: an object freed and reused is wrong for one window at most.
	resetNames()
}

// regWalker also reads a stack from the registers of an on-CPU thread (Node, JVM). The registers
// come from a BPF sample a moment old, so the walk validates every frame like any other read.
type regWalker interface {
	StackFrom(pc, sp, fp uint64) []string
}

// budgetMem ends a walk once the sampling tick has used its share of reads.
type budgetMem struct {
	memReader
	left *int
}

var errBudget = errors.New("read budget used up")

func (b *budgetMem) ReadAt(a uint64, p []byte) error {
	if *b.left <= 0 {
		return errBudget
	}
	*b.left--
	return b.memReader.ReadAt(a, p)
}

// rmem adds typed little-endian reads to a memReader.
type rmem struct{ memReader }

func (m rmem) u64(a uint64) (uint64, error) {
	var b [8]byte
	err := m.ReadAt(a, b[:])
	return binary.LittleEndian.Uint64(b[:]), err
}

func (m rmem) u32(a uint64) (uint32, error) {
	var b [4]byte
	err := m.ReadAt(a, b[:])
	return binary.LittleEndian.Uint32(b[:]), err
}

func (m rmem) u16(a uint64) (uint16, error) {
	var b [2]byte
	err := m.ReadAt(a, b[:])
	return binary.LittleEndian.Uint16(b[:]), err
}

func (m rmem) u8(a uint64) (uint8, error) {
	var b [1]byte
	err := m.ReadAt(a, b[:])
	return b[0], err
}

// cstr reads a NUL-terminated string of at most max bytes; it reads in small pieces because the
// string can end right before an unmapped page.
func (m rmem) cstr(a uint64, limit int) (string, error) {
	var out []byte
	for len(out) < limit {
		n := min(32-int(a%32), limit-len(out)) // never crosses a page more than the string does
		b := make([]byte, n)
		if err := m.ReadAt(a, b); err != nil {
			return "", err
		}
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(append(out, b[:i]...)), nil
		}
		out = append(out, b...)
		a += uint64(n)
	}
	return "", errors.New("string too long")
}

// printable says a name read from a target is text, not bytes from a torn read.
func printable(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
