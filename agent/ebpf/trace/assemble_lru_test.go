package trace

import "testing"

// TestAssemblerEvictsLRUConn checks that a flood of new connections evicts the least-recently-used
// connection (keeping the map at maxConns) instead of clearing all pairing state, and that a
// touched connection survives while Forget drops one cleanly.
func TestAssemblerEvictsLRUConn(t *testing.T) {
	a := NewAssembler()
	ev := func(pid uint32) Event { return Event{PID: pid, FD: 1, Dir: Send} }
	for i := 0; i < maxConns; i++ {
		a.Handle(ev(uint32(i)))
	}
	if len(a.conns) != maxConns {
		t.Fatalf("conns = %d, want %d", len(a.conns), maxConns)
	}
	// conn 0 is oldest; touch it so conn 1 becomes least-recently-used, then overflow by one.
	a.Handle(ev(0))
	a.Handle(ev(uint32(maxConns)))
	if len(a.conns) != maxConns {
		t.Fatalf("conns after overflow = %d, want %d", len(a.conns), maxConns)
	}
	if _, ok := a.conns[connKey{pid: 1, fd: 1}]; ok {
		t.Fatal("conn 1 should have been evicted as least-recently-used")
	}
	if _, ok := a.conns[connKey{pid: 0, fd: 1}]; !ok {
		t.Fatal("conn 0 was touched and must survive eviction")
	}
	a.Forget(0, 1)
	if _, ok := a.conns[connKey{pid: 0, fd: 1}]; ok {
		t.Fatal("Forget should drop the connection")
	}
	if a.order.Len() != len(a.conns) {
		t.Fatalf("lru list length %d out of sync with map length %d", a.order.Len(), len(a.conns))
	}
}
