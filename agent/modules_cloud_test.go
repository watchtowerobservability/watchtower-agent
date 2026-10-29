package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCloudAndVirtModulesRemoteMayOnlyToggle(t *testing.T) {
	reg := NewRegistry(&LocalConfig{StateDir: t.TempDir()})
	local := map[string]json.RawMessage{
		"aws":            json.RawMessage(`{"namespaces":["AWS/Lambda"]}`),
		"azure_eventhub": json.RawMessage(`{"topics":["h"],"connection_string_env":"AZ_CS"}`),
		"proxmox":        json.RawMessage(`{"targets":[{"name":"c","url":"https://pve:8006","token_id":"a@b!c","token_secret_env":"PVE"}]}`),
		"vsphere":        json.RawMessage(`{"targets":[{"name":"v","url":"https://vc/sdk"}]}`),
	}
	remote := &RemoteConfig{Modules: map[string]json.RawMessage{
		"aws":            json.RawMessage(`{"enabled":false}`),
		"azure_eventhub": json.RawMessage(`{"connection_string":"Endpoint=evil"}`),
		"proxmox":        json.RawMessage(`{"targets":[{"url":"https://evil"}]}`),
		"vsphere":        json.RawMessage(`{"interval":"30s"}`),
	}}
	var warns []string
	p := Merge(reg, local, remote, func(m string) { warns = append(warns, m) })
	if !strings.Contains(string(p["aws"]), `"enabled":false`) || !strings.Contains(string(p["aws"]), "AWS/Lambda") {
		t.Fatalf("aws: %s", p["aws"])
	}
	if strings.Contains(string(p["azure_eventhub"]), "evil") || strings.Contains(string(p["proxmox"]), "evil") || len(warns) != 2 {
		t.Fatalf("remote must not set credentials or targets (warns %v)", warns)
	}
	if !strings.Contains(string(p["vsphere"]), "30s") {
		t.Fatalf("vsphere: %s", p["vsphere"])
	}
}
