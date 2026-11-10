//go:build linux

package autoinst

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func upgradeFixture(t *testing.T) (Config, *[]string) {
	t.Helper()
	dir := t.TempDir()
	oldC, oldP, oldProbe, oldRestart := confPath, preloadPath, probeCmd, restartUnit
	t.Cleanup(func() { confPath, preloadPath, probeCmd, restartUnit = oldC, oldP, oldProbe, oldRestart })
	confPath, preloadPath, probeCmd = filepath.Join(dir, "autoinst.conf"), filepath.Join(dir, "ld.so.preload"), "/bin/true"
	var restarted []string
	restartUnit = func(_ context.Context, u string) error { restarted = append(restarted, u); return nil }
	c := Config{Enabled: true, AgentsDir: dir, StateFile: filepath.Join(dir, "state.json"),
		Rules: []Rule{{Exe: "/usr/bin/java", Lang: "java", Service: "shop", Unit: "shop.service"}}}
	if err := os.WriteFile(shim(c), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return c, &restarted
}

func TestUpgradeSwitchesVersionKeepsItAndRestartsOnlyWhenAllowed(t *testing.T) {
	c, restarted := upgradeFixture(t)
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(c.AgentsDir, "versions", "2.1.0", "java"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Upgrade(ctx, c, "java", "shop", "9.9.9", false); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("missing version: %v", err)
	}
	if err := Upgrade(ctx, c, "java", "other", "2.1.0", false); err == nil {
		t.Fatal("a service without a rule must be refused")
	}
	// restart asked by the job, but the machine did not opt in
	if err := Upgrade(ctx, c, "java", "shop", "2.1.0", true); err != nil {
		t.Fatal(err)
	}
	if len(*restarted) != 0 {
		t.Fatalf("restarted without allow_restart: %v", *restarted)
	}
	conf, _ := os.ReadFile(confPath)
	if !strings.Contains(string(conf), "-javaagent:"+c.AgentsDir+"/versions/2.1.0/java/javaagent.jar") {
		t.Fatalf("conf %q", conf)
	}
	if got := WithState(c).Versions["java"]; got != "2.1.0" {
		t.Fatalf("stored version %q", got)
	}
	c.AllowRestart = true
	if err := Upgrade(ctx, c, "java", "shop", "2.1.0", true); err != nil {
		t.Fatal(err)
	}
	if len(*restarted) != 1 || (*restarted)[0] != "shop.service" {
		t.Fatalf("restarted %v", *restarted)
	}
}

func TestApplies(t *testing.T) {
	c := Config{Rules: []Rule{{Exe: "/usr/bin/orders", Lang: "java"}, {Exe: "x", Lang: "python", Service: "billing"}}}
	for _, tc := range []struct {
		lang, svc string
		want      bool
	}{{"java", "orders", true}, {"python", "billing", true}, {"java", "billing", false}, {"nodejs", "orders", false}} {
		if got := Applies(c, tc.lang, tc.svc); got != tc.want {
			t.Errorf("Applies(%s,%s)=%v", tc.lang, tc.svc, got)
		}
	}
}

func TestValidateRejectsBadVersionAndUnit(t *testing.T) {
	if (Config{Versions: map[string]string{"java": "../x"}}).Validate() == nil {
		t.Fatal("path in version")
	}
	if (Config{Rules: []Rule{{Exe: "a", Lang: "java", Unit: "a b"}}}).Validate() == nil {
		t.Fatal("bad unit")
	}
}
