package runtimesec

import (
	"encoding/binary"
	"errors"
	"testing"
)

type fakeMap struct {
	m map[denyKey]uint32
}

func (f *fakeMap) Put(k denyKey, v uint32) error { f.m[k] = v; return nil }
func (f *fakeMap) Delete(k denyKey) error        { delete(f.m, k); return nil }
func (f *fakeMap) Keys() ([]denyKey, error) {
	var out []denyKey
	for k := range f.m {
		out = append(out, k)
	}
	return out, nil
}

func blockPolicy() Policy {
	return Policy{Rules: []Rule{
		{ID: "no_nc", Kind: "exec", Severity: "high", Action: "block", Match: map[string]any{"paths": []string{"/usr/bin/nc"}}},
		{ID: "ro_shadow", Kind: "file", Severity: "high", Action: "block", Match: map[string]any{"op": "write", "paths": []string{"/etc/shadow", "/etc/late"}}},
		{ID: "watch", Kind: "exec", Severity: "low", Action: "alert"},
	}}
}

func fakeStat(path string) (uint64, uint64, bool, error) {
	switch path {
	case "/usr/bin/nc":
		return 0x801, 100, false, nil // dev 8:1
	case "/etc/shadow":
		return 0x801, 200, false, nil
	}
	return 0, 0, false, errors.New("not found")
}

func TestBlockPolicyIsValidAndPlanned(t *testing.T) {
	p := blockPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !p.hasBlockRules() || (Policy{Rules: p.Rules[2:]}).hasBlockRules() {
		t.Fatal("hasBlockRules wrong")
	}
	plan, unresolved := BlockPlan(p, fakeStat)
	if len(plan) != 2 || len(unresolved) != 1 || unresolved[0] != "/etc/late" {
		t.Fatalf("plan=%v unresolved=%v", plan, unresolved)
	}
	if plan[0].Kind != "exec" || plan[0].Flags != flagAny || plan[0].Key != (denyKey{Ino: 100, Dev: 8<<20 | 1}) {
		t.Fatalf("exec entry: %+v", plan[0])
	}
	if plan[1].Kind != "file" || plan[1].Flags != flagWrite {
		t.Fatalf("a write rule must refuse writes only: %+v", plan[1])
	}
}

func TestKernelDevMatchesTheKernelEncoding(t *testing.T) {
	// major 259, minor 3: new_encode_dev puts the minor's high bits above bit 12 and major at bit 8.
	d := uint64(259)<<8 | 3
	if got := kernelDev(d); got != 259<<20|3 {
		t.Fatalf("got %x", got)
	}
	// minor 0x1234: low byte stays, the rest moves up by 12 bits.
	d = uint64(8)<<8 | 0x34 | uint64(0x12)<<20
	if got := kernelDev(d); got != 8<<20|0x1234 {
		t.Fatalf("got %x", got)
	}
}

func TestSyncDenyAddsAndRemoves(t *testing.T) {
	a, b, c := denyKey{Ino: 1}, denyKey{Ino: 2}, denyKey{Ino: 3}
	m := &fakeMap{m: map[denyKey]uint32{a: flagAny, b: flagAny}}
	added, removed, err := syncDeny(m, map[denyKey]uint32{b: flagWrite, c: flagAny})
	if err != nil || added != 1 || removed != 1 {
		t.Fatalf("added=%d removed=%d err=%v", added, removed, err)
	}
	if _, ok := m.m[a]; ok || m.m[b] != flagWrite || m.m[c] != flagAny {
		t.Fatalf("map = %v", m.m)
	}
}

func TestWithoutTheBPFLSMBlockRulesAreRefused(t *testing.T) {
	for list, want := range map[string]bool{
		"lockdown,capability,landlock,yama,apparmor,bpf\n": true,
		"lockdown,capability,yama,apparmor\n":              false,
		"":                                                 false,
		"bpfx,capability":                                  false,
	} {
		if lsmListHasBPF(list) != want {
			t.Errorf("lsmListHasBPF(%q) != %v", list, want)
		}
	}
	// Off Linux, and on Linux without the LSM, Run must refuse a block policy instead of running it
	// as monitor-only; the non-Linux loader shares errNoBPFLSM.
	if errNoBPFLSM == nil {
		t.Fatal("no refusal error")
	}
}

func TestDeniedRecordDecodes(t *testing.T) {
	b := make([]byte, deniedSize)
	binary.LittleEndian.PutUint64(b[8:], 77)
	binary.LittleEndian.PutUint32(b[16:], 8<<20|1)
	binary.LittleEndian.PutUint32(b[20:], 4242)
	binary.LittleEndian.PutUint32(b[24:], 0)
	copy(b[32:], "nc")
	d, ok := decodeDenied(b)
	if !ok || d.Kind != "exec" || d.PID != 4242 || d.Comm != "nc" || d.Key != (denyKey{Ino: 77, Dev: 8<<20 | 1}) {
		t.Fatalf("%+v ok=%v", d, ok)
	}
	if _, ok := decodeDenied(b[:10]); ok {
		t.Fatal("short record accepted")
	}
}
