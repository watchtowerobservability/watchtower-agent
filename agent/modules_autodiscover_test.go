package main

import (
	"encoding/json"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/k8s"
)

func TestAutodiscoverBindsOnlyConfiguredIntegrationModules(t *testing.T) {
	m := NewRegistry(&LocalConfig{StateDir: t.TempDir()})["autodiscovery"].(autodiscoverModule)
	base := map[string]json.RawMessage{
		"redis": json.RawMessage(`{"addr":"%%host%%:%%port%%","interval":"15s"}`),
		"hw":    json.RawMessage(`{"redfish":[{"url":"https://%%host%%"}]}`),
	}
	_, cfg, err := m.bind(adTarget{ip: "10.1.2.3", port: 6380, integration: "redis"}, base)
	if err != nil || string(cfg) != `{"addr":"10.1.2.3:6380","interval":"15s"}` {
		t.Fatalf("redis bind = %s, %v", cfg, err)
	}
	if _, _, err := m.bind(adTarget{ip: "10.1.2.3", port: 1, integration: "hw"}, base); err == nil {
		t.Fatal("a non-integration module must never be bound from an annotation")
	}
	if _, _, err := m.bind(adTarget{ip: "10.1.2.3", port: 1, integration: "mysql"}, base); err == nil {
		t.Fatal("an integration without a local base config must not be bound")
	}
}

func TestTemplateConfigBracketsIPv6AndNeedsHost(t *testing.T) {
	cfg, err := templateConfig(json.RawMessage(`{"addr":"%%host%%:%%port%%"}`), "fd00::1", 9000)
	if err != nil || string(cfg) != `{"addr":"[fd00::1]:9000"}` {
		t.Fatalf("got %s, %v", cfg, err)
	}
	if _, err := templateConfig(json.RawMessage(`{"addr":"db.internal:5432"}`), "10.0.0.1", 1); err == nil {
		t.Fatal("a base config without %%host%% would scrape a fixed address for every pod")
	}
	if _, err := templateConfig(json.RawMessage(`{"addr":"%%host%%"}`), `1.2.3.4","x":"`, 1); err == nil {
		t.Fatal("a non-IP must be refused")
	}
}

func TestDockerLabelTargets(t *testing.T) {
	cs := []container.Info{
		{ID: "a", Name: "api", State: "running", IP: "172.17.0.2", Ports: []int{8080, 9090},
			Labels: map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/port": "9090"}},
		{ID: "b", Name: "cache", State: "running", IP: "172.17.0.3", Ports: []int{6379},
			Labels: map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/integration": "redis"}},
		{ID: "c", Name: "off", State: "running", IP: "172.17.0.4", Ports: []int{80}},
		{ID: "d", Name: "stopped", State: "exited", IP: "172.17.0.5", Ports: []int{80}, Labels: map[string]string{"watchtower.dev/scrape": "true"}},
		{ID: "e", Name: "badpath", State: "running", IP: "172.17.0.6", Ports: []int{80},
			Labels: map[string]string{"watchtower.dev/scrape": "true", "watchtower.dev/path": "metrics#x"}},
	}
	got := labelTargets(container.LabelTargets(cs))
	if len(got) != 2 || got[0].port != 9090 || got[0].path != "/metrics" || got[1].integration != "redis" || got[1].port != 6379 {
		t.Fatalf("targets = %+v", got)
	}
	if got[0].labels["container.name"] != "api" {
		t.Fatalf("labels = %v", got[0].labels)
	}
}

func TestPodTargetsCarryPodIdentity(t *testing.T) {
	got := podTargets([]k8s.Target{{Namespace: "shop", Pod: "cart-1", UID: "u1", IP: "10.0.0.9", Port: 9102, Path: "/metrics"}})
	if len(got) != 1 || got[0].labels["k8s.pod.name"] != "cart-1" || got[0].key != "pod/shop/cart-1:9102" {
		t.Fatalf("got %+v", got)
	}
}
