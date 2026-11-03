package rulesync

import (
	"context"
	"net/http"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
)

func TestLLDPrototypeMakesOneRulePerMount(t *testing.T) {
	protos := []Prototype{{Kind: host.KindFilesystem, Alert: "Disk full on {{host}} {{mountpoint}}",
		Expr: `system_filesystem_utilization{host_name="{{host}}",mountpoint="{{mountpoint}}"} > 0.9`, For: "10m",
		Labels: map[string]string{"severity": "high"}, Annotations: map[string]string{"summary": "{{mountpoint}} ({{type}}) is over 90%"}}}
	objs := []host.Object{
		{Kind: host.KindFilesystem, Name: "/data", Labels: map[string]string{"mountpoint": "/data", "device": "sdb1", "type": "xfs"}},
		{Kind: host.KindFilesystem, Name: `/mnt/we"ird`, Labels: map[string]string{"mountpoint": `/mnt/we"ird`, "type": "ext4"}},
		{Kind: host.KindNIC, Name: "eth0", Labels: map[string]string{"device": "eth0"}},
	}
	g := LLDGroups("web-1", protos, objs)
	grp, ok := g["lld.web-1.filesystem"]
	if len(g) != 1 || !ok {
		t.Fatalf("groups: %v", g)
	}
	rules := grp["rules"].([]map[string]any)
	if len(rules) != 2 {
		t.Fatalf("rules: %v", rules)
	}
	if rules[0]["alert"] != "Disk full on web-1 /data" || rules[0]["for"] != "10m" {
		t.Errorf("rule 0: %v", rules[0])
	}
	if rules[1]["expr"] != `system_filesystem_utilization{host_name="web-1",mountpoint="/mnt/we\"ird"} > 0.9` {
		t.Errorf("expr not escaped: %v", rules[1]["expr"])
	}
	l := rules[0]["labels"].(map[string]string)
	if l["mountpoint"] != "/data" || l["device"] != "sdb1" || l["severity"] != "high" || l["host_name"] != "web-1" {
		t.Errorf("labels: %v", l)
	}
	if a := rules[0]["annotations"].(map[string]string); a["summary"] != "/data (xfs) is over 90%" {
		t.Errorf("annotations: %v", a)
	}
}

func TestLLDSyncDropsTheGroupWhenObjectsVanish(t *testing.T) {
	protos := []Prototype{{Kind: host.KindNIC, Alert: "NIC errors {{device}}", Expr: `rate(x{device="{{device}}"}[5m]) > 0`}}
	objs := []host.Object{{Kind: host.KindNIC, Name: "eth0", Labels: map[string]string{"device": "eth0"}}}
	var calls []string
	s := &syncer{
		want: func(context.Context) (map[string]map[string]any, error) { return LLDGroups("h", protos, objs), nil },
		do: func(_ context.Context, m, rel string, _ any) error {
			calls = append(calls, m+" "+rel)
			return nil
		},
		synced: map[string][32]byte{},
	}
	ctx := context.Background()
	if err := s.once(ctx); err != nil {
		t.Fatal(err)
	}
	objs = nil
	if err := s.once(ctx); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != http.MethodPut+" rule-groups/lld.h.nic" || calls[1] != http.MethodDelete+" rule-groups/lld.h.nic" {
		t.Fatalf("calls: %v", calls)
	}
	if (LLDConfig{Prototypes: []Prototype{{Kind: "gpu", Alert: "a", Expr: "b"}}}).validate() == nil {
		t.Fatal("unsupported kind accepted")
	}
}
