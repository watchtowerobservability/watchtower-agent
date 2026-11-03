package ebpf

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Limits of the DWARF unwinding state shipped to the kernel (they size the BPF maps too).
const (
	maxUnwindMappings = 8       // executable mappings per process with a table (binary + libs)
	maxUnwindProcs    = 1024    // processes with tables
	maxUnwindRows     = 1 << 19 // rows over all binaries (16 bytes each: 8 MiB)
	maxBinaryRows     = 1 << 17 // a bigger binary gets no table (frame pointers)
	maxNewProcs       = 64      // tables built per upload window, bounds the agent's CPU
)

// unwindMapping mirrors `struct umap` in bpf/cpu_dwarf.bpf.c: rows[Off:Off+Len] cover
// [Start, End), a runtime PC maps to a table PC as pc - Bias.
type unwindMapping struct {
	Start, End, Bias uint64
	Off, Len         uint32
}

// unwindProc mirrors `struct uproc`.
type unwindProc struct {
	N    uint32
	_    uint32
	Maps [maxUnwindMappings]unwindMapping
}

// unwindSink is where the cache writes: the BPF maps on Linux, a fake in tests.
type unwindSink interface {
	putRows(off uint32, rows []UnwindRow) error
	putProc(pid uint32, p *unwindProc) error
	delProc(pid uint32) error
}

type binTable struct {
	off, n uint32
	shift  uint64
	ok     bool
}

// unwindCache builds unwind tables of the processes being sampled, once per binary, and keeps
// at most maxUnwindProcs processes (least recently seen out first). A table lives while a process
// uses it; its rows then go back to a free list that later tables reuse.
type unwindCache struct {
	sink   unwindSink
	proc   string // /proc
	bins   map[string]binTable
	refs   map[string]int      // processes using each table
	uses   map[uint32][]string // pid -> its tables
	free   []rowExtent         // freed row ranges, sorted and merged
	next   uint32              // rows past this were never used
	full   bool                // a table did not fit: the oldest processes go at the next window
	procs  map[uint32]uint64   // pid -> window last seen
	window uint64
	// tableOf reads one binary's rows and the link vaddr minus file offset of its text segment.
	tableOf func(path string, off uint64) ([]UnwindRow, uint64, error)
}

// rowExtent is a free range of rows.
type rowExtent struct{ off, n uint32 }

func newUnwindCache(sink unwindSink) *unwindCache {
	return &unwindCache{sink: sink, proc: "/proc", bins: map[string]binTable{}, refs: map[string]int{},
		uses: map[uint32][]string{}, procs: map[uint32]uint64{}, tableOf: elfTable}
}

// elfTable reads the rows of path and the vaddr-minus-offset shift of the PT_LOAD segment
// holding file offset off.
func elfTable(path string, off uint64) ([]UnwindRow, uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var shift uint64
	found := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Off <= off && off < p.Off+p.Filesz {
			shift, found = p.Vaddr-p.Off, true
			break
		}
	}
	if !found {
		return nil, 0, errors.New("no PT_LOAD segment holds the mapping")
	}
	rows, err := TableForELF(f)
	return rows, shift, err
}

// Observe gives every pid of a window a table (bounded per window) and evicts the oldest.
func (c *unwindCache) Observe(pids []uint32) {
	c.window++
	if c.full {
		c.evictOldest(max(len(c.procs)/4, 1)) // frees their tables for the ones that did not fit
		c.full = false
	}
	built := 0
	for _, pid := range pids {
		if _, ok := c.procs[pid]; ok {
			c.procs[pid] = c.window
			continue
		}
		if built >= maxNewProcs {
			continue
		}
		built++
		c.evict()
		if c.add(pid) == nil {
			c.procs[pid] = c.window
		}
	}
}

func (c *unwindCache) evict() {
	if len(c.procs) >= maxUnwindProcs {
		c.evictOldest(1)
	}
}

// evictOldest drops the n least recently seen processes and the tables only they used.
func (c *unwindCache) evictOldest(n int) {
	pids := make([]uint32, 0, len(c.procs))
	for pid := range c.procs {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return c.procs[pids[i]] < c.procs[pids[j]] })
	for _, pid := range pids[:min(n, len(pids))] {
		delete(c.procs, pid)
		_ = c.sink.delProc(pid)
		for _, key := range c.uses[pid] {
			c.refs[key]--
			c.drop(key)
		}
		delete(c.uses, pid)
	}
}

// drop frees a table no process uses any more.
func (c *unwindCache) drop(key string) {
	if c.refs[key] > 0 {
		return
	}
	delete(c.refs, key)
	if t, ok := c.bins[key]; ok && t.ok {
		c.release(t.off, t.n)
	}
	delete(c.bins, key)
}

// alloc takes n rows, first fit from the free list, else past next.
func (c *unwindCache) alloc(n uint32) (uint32, bool) {
	for i, e := range c.free {
		if e.n < n {
			continue
		}
		if e.n == n {
			c.free = append(c.free[:i], c.free[i+1:]...)
		} else {
			c.free[i] = rowExtent{e.off + n, e.n - n}
		}
		return e.off, true
	}
	if c.next+n > maxUnwindRows {
		return 0, false
	}
	c.next += n
	return c.next - n, true
}

// release gives rows back, merging with neighbours; rows that end at next shrink it instead.
func (c *unwindCache) release(off, n uint32) {
	i := sort.Search(len(c.free), func(i int) bool { return c.free[i].off > off })
	c.free = append(c.free, rowExtent{})
	copy(c.free[i+1:], c.free[i:])
	c.free[i] = rowExtent{off, n}
	merged := c.free[:0]
	for _, e := range c.free {
		if k := len(merged) - 1; k >= 0 && merged[k].off+merged[k].n == e.off {
			merged[k].n += e.n
			continue
		}
		merged = append(merged, e)
	}
	c.free = merged
	if k := len(c.free) - 1; k >= 0 && c.free[k].off+c.free[k].n == c.next {
		c.next = c.free[k].off
		c.free = c.free[:k]
	}
}

func (c *unwindCache) add(pid uint32) error {
	dir := filepath.Join(c.proc, strconv.Itoa(int(pid)))
	f, err := os.Open(filepath.Join(dir, "maps"))
	if err != nil {
		return err
	}
	ms := ParseMaps(f)
	f.Close()
	var p unwindProc
	var keys []string
	for _, m := range ms {
		if p.N == maxUnwindMappings {
			break
		}
		if m.Path == "" || m.Path[0] != '/' {
			continue // anonymous, [vdso], JIT: frame pointers
		}
		key, t := c.binary(filepath.Join(dir, "root", m.Path), m.Offset)
		if !t.ok {
			continue
		}
		keys = append(keys, key)
		// table pc = file offset + shift = pc - Start + Offset + shift
		p.Maps[p.N] = unwindMapping{Start: m.Start, End: m.End, Bias: m.Start - m.Offset - t.shift, Off: t.off, Len: t.n}
		p.N++
	}
	if p.N == 0 {
		return errors.New("no mapping has unwind info")
	}
	if err := c.sink.putProc(pid, &p); err != nil {
		for _, key := range keys {
			c.drop(key) // a table built for this process alone goes again
		}
		return err
	}
	for _, key := range keys {
		c.refs[key]++
	}
	c.uses[pid] = keys
	return nil
}

// binary returns the key and table of path for a mapping at file offset off, read once.
func (c *unwindCache) binary(path string, off uint64) (string, binTable) {
	id := BuildID(path) // the same binary in many containers shares one table
	if id == "" {
		id = path
	}
	key := id + "@" + strconv.FormatUint(off, 16)
	if t, ok := c.bins[key]; ok {
		return key, t
	}
	t := binTable{}
	rows, shift, err := c.tableOf(path, off)
	if err != nil || len(rows) == 0 || len(rows) > maxBinaryRows {
		c.bins[key] = t // frame pointers for this binary
		return key, t
	}
	at, ok := c.alloc(uint32(len(rows)))
	if !ok {
		c.full = true
		return key, t // not cached: retried once older processes are evicted
	}
	if c.sink.putRows(at, rows) != nil {
		c.release(at, uint32(len(rows)))
		c.bins[key] = t
		return key, t
	}
	t = binTable{off: at, n: uint32(len(rows)), shift: shift, ok: true}
	c.bins[key] = t
	return key, t
}
