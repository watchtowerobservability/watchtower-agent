package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInfraModulesRemoteMayOnlyToggle(t *testing.T) {
	reg := NewRegistry(&LocalConfig{StateDir: t.TempDir()})
	local := map[string]json.RawMessage{"logs": json.RawMessage(`{"files":[{"path":"/var/log/app.log"}]}`)}
	remote := &RemoteConfig{Modules: map[string]json.RawMessage{
		"host":      json.RawMessage(`{"interval":"5s"}`),
		"logs":      json.RawMessage(`{"files":[{"path":"/etc/shadow"}]}`),
		"container": json.RawMessage(`{"enabled":false}`),
		"gpu":       json.RawMessage(`{"nvidia_smi_path":"/tmp/evil"}`),
	}}
	var warns []string
	p := Merge(reg, local, remote, func(m string) { warns = append(warns, m) })
	if string(p["host"]) != `{"interval":"5s"}` {
		t.Fatalf("host: %s", p["host"])
	}
	if !strings.Contains(string(p["logs"]), "/var/log/app.log") || strings.Contains(string(p["logs"]), "shadow") {
		t.Fatalf("remote must not name log paths: %s", p["logs"])
	}
	if p["container"] != nil {
		t.Fatalf("a module the local file does not define is not started remotely: %s", p["container"])
	}
	if p["gpu"] != nil || len(warns) != 3 {
		t.Fatalf("gpu path must be refused (warns %v)", warns)
	}
}
