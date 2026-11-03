package ebpf

// pyHz is the rate Python stacks are read at: each read walks the target's memory.
const pyHz = 19

// pyFolder counts Python stacks as Entries whose "addresses" index a name table, so they go through
// the same Fold as native stacks.
type pyFolder struct {
	names  []string
	ids    map[string]uint64
	stacks map[string]*Entry
}

func newPyFolder() *pyFolder {
	return &pyFolder{ids: map[string]uint64{}, stacks: map[string]*Entry{}}
}

func (f *pyFolder) add(pid uint32, frames []string) {
	addrs := make([]uint64, len(frames))
	key := make([]byte, 0, 8*len(frames)+4)
	key = append(key, byte(pid), byte(pid>>8), byte(pid>>16), byte(pid>>24))
	for i, n := range frames {
		id, ok := f.ids[n]
		if !ok {
			f.names = append(f.names, n)
			id = uint64(len(f.names))
			f.ids[n] = id
		}
		addrs[i] = id
		for s := 0; s < 64; s += 8 {
			key = append(key, byte(id>>s))
		}
	}
	e := f.stacks[string(key)]
	if e == nil {
		e = &Entry{PID: pid, User: addrs}
		f.stacks[string(key)] = e
	}
	e.Value += uint64(1_000_000_000 / pyHz)
}

func (f *pyFolder) entries() []Entry {
	out := make([]Entry, 0, len(f.stacks))
	for _, e := range f.stacks {
		out = append(out, *e)
	}
	return out
}

// pyResolver names the table's frames and takes process metadata from the host resolver.
type pyResolver struct {
	Resolver
	names []string
}

func (r pyResolver) User(_ uint32, addr uint64) Frame {
	if addr == 0 || addr > uint64(len(r.names)) {
		return Frame{}
	}
	return Frame{Addr: addr, Name: r.names[addr-1]}
}
