package ebpf

import (
	"strings"
	"testing"
)

func TestNSPid(t *testing.T) {
	status := "Name:\tpython3\nPid:\t4242\nNSpid:\t4242\t17\nPPid:\t1\n"
	if n, ok := NSPid(strings.NewReader(status)); !ok || n != 17 {
		t.Fatalf("NSPid = %d, %v; want 17", n, ok)
	}
	if n, ok := NSPid(strings.NewReader("NSpid:\t99\n")); !ok || n != 99 {
		t.Fatalf("host pid: %d, %v", n, ok)
	}
	if _, ok := NSPid(strings.NewReader("Name:\tx\n")); ok {
		t.Fatal("no NSpid line must not parse")
	}
	p := ParsePerfMap(strings.NewReader("7f00 10 py::main:/app/m.py\n"))
	if name, ok := p.Lookup(0x7f08); !ok || name != "py::main:/app/m.py" {
		t.Fatalf("lookup = %q, %v", name, ok)
	}
}
