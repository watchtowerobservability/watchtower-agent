package runtimesec

import (
	"encoding/binary"
	"testing"
)

// encEvent builds a raw struct rt_event (312 bytes) the way bpf/runtimesec.bpf.c writes it, so the
// decode + match path is exercised without a kernel.
func encEvent(kind, op uint32, pid, dport uint32, comm, path string) []byte {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint32(b[16:], pid)
	le.PutUint32(b[24:], kind)
	le.PutUint32(b[28:], op)
	le.PutUint32(b[32:], dport)
	copy(b[40:56], comm)
	copy(b[56:312], path)
	return b
}

func TestDecodeEventKindsAndStrings(t *testing.T) {
	ev, ok := DecodeEvent(encEvent(kindFile, opWrite, 1234, 0, "vi", "/etc/passwd"))
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.Kind != "file" || ev.Op != "write" || ev.PID != 1234 || ev.Comm != "vi" || ev.Path != "/etc/passwd" {
		t.Fatalf("decoded wrong: %+v", ev)
	}
	if _, ok := DecodeEvent(make([]byte, EventSize-1)); ok {
		t.Error("short buffer should not decode")
	}
	if _, ok := DecodeEvent(encEvent(99, 0, 1, 0, "x", "y")); ok {
		t.Error("unknown kind should not decode")
	}
}

// TestWriteEtcPasswdProducesOneSignal is the acceptance case: a write to /etc/passwd in a container
// trips exactly one default-policy rule, carrying the service name and the process.
func TestWriteEtcPasswdProducesOneSignal(t *testing.T) {
	ev, _ := DecodeEvent(encEvent(kindFile, opWrite, 4321, 0, "bash", "/etc/passwd"))
	ev.InContainer = true
	ev.Service = "prod/api-7f9"
	hits := DefaultPolicy().Match(ev)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Rule.ID != "write_sensitive_file" || h.Rule.Severity != "high" {
		t.Errorf("wrong rule: %+v", h.Rule)
	}
	if h.Detail["path"] != "/etc/passwd" || h.Detail["comm"] != "bash" || h.Detail["op"] != "write" {
		t.Errorf("detail missing process/path: %v", h.Detail)
	}

	// The emitter carries the service name as the signal entity.
	s := &fakeSink{}
	NewEmitter(s, "node-1").Signal(h.Rule, ev.Service, h.Detail)
	if s.attrs["security.entity"] != "prod/api-7f9" || s.attrs["security.rule"] != "write_sensitive_file" {
		t.Errorf("signal attrs wrong: %v", s.attrs)
	}
}

func TestMatchPerKind(t *testing.T) {
	// exec shell in container: in_container required.
	sh := func(in bool) Event {
		e, _ := DecodeEvent(encEvent(kindExec, 0, 9, 0, "bash", "/bin/bash"))
		e.InContainer = in
		return e
	}
	if got := DefaultPolicy().Match(sh(true)); len(got) != 1 || got[0].Rule.ID != "shell_in_container" {
		t.Errorf("shell in container: %+v", got)
	}
	if got := DefaultPolicy().Match(sh(false)); len(got) != 0 {
		t.Errorf("shell outside container must not trip in_container rule: %+v", got)
	}

	// file: write under /usr/bin matches the prefix rule; a read there does not.
	wr, _ := DecodeEvent(encEvent(kindFile, opWrite, 9, 0, "cp", "/usr/bin/evil"))
	if got := DefaultPolicy().Match(wr); len(got) != 1 || got[0].Rule.ID != "write_below_system_bin" {
		t.Errorf("write below bin: %+v", got)
	}
	rd, _ := DecodeEvent(encEvent(kindFile, 0, 9, 0, "cat", "/usr/bin/ls"))
	if got := DefaultPolicy().Match(rd); len(got) != 0 {
		t.Errorf("read below bin should not trip the write rule: %+v", got)
	}

	// network: a custom deny_ports rule catches the egress port.
	pol := Policy{Rules: []Rule{{ID: "block_6379", Kind: "network", Severity: "medium", Action: "alert",
		Match: map[string]any{"direction": "egress", "deny_ports": []int{6379}}}}}
	netEv, _ := DecodeEvent(encEvent(kindNetwork, opWrite, 9, 6379, "redis-cli", ""))
	if got := pol.Match(netEv); len(got) != 1 || got[0].Detail["dport"] != "6379" {
		t.Errorf("deny_ports egress: %+v", got)
	}
	other, _ := DecodeEvent(encEvent(kindNetwork, opWrite, 9, 443, "curl", ""))
	if got := pol.Match(other); len(got) != 0 {
		t.Errorf("port not in deny list must not trip: %+v", got)
	}
}
