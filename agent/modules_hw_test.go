package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSNMPAndHWRemoteMayOnlyToggle(t *testing.T) {
	reg := NewRegistry(&LocalConfig{StateDir: t.TempDir()})
	local := map[string]json.RawMessage{
		"snmp": json.RawMessage(`{"targets":[{"name":"sw1","address":"192.0.2.1","community":"private"}]}`),
		"hw":   json.RawMessage(`{"nut":[{"name":"u","address":"192.0.2.2","ups":"rack"}]}`),
	}
	remote := &RemoteConfig{Modules: map[string]json.RawMessage{
		"snmp": json.RawMessage(`{"targets":[{"name":"evil","address":"203.0.113.9","community":"x"}]}`),
		"hw":   json.RawMessage(`{"enabled":false,"interval":"2m"}`),
	}}
	var warns []string
	p := Merge(reg, local, remote, func(m string) { warns = append(warns, m) })
	if !strings.Contains(string(p["snmp"]), "192.0.2.1") || strings.Contains(string(p["snmp"]), "evil") || len(warns) != 1 {
		t.Fatalf("remote must not name devices: %s (warns %v)", p["snmp"], warns)
	}
	if !strings.Contains(string(p["hw"]), `"enabled":false`) || !strings.Contains(string(p["hw"]), "rack") {
		t.Fatalf("hw = %s", p["hw"])
	}
	for _, w := range warns {
		if strings.Contains(w, "203.0.113.9") {
			t.Fatalf("warning echoes the remote's address: %s", w)
		}
	}
}
