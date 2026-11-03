//go:build linux

package autoinst

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyAddsShimOnceAndRevertsOnFailure(t *testing.T) {
	dir := t.TempDir()
	oldC, oldP, oldProbe := confPath, preloadPath, probeCmd
	t.Cleanup(func() { confPath, preloadPath, probeCmd = oldC, oldP, oldProbe })
	confPath, preloadPath = filepath.Join(dir, "etc", "autoinst.conf"), filepath.Join(dir, "ld.so.preload")
	if err := os.WriteFile(preloadPath, []byte("/usr/lib/other.so"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := Config{Enabled: true, AgentsDir: dir, Rules: []Rule{{Exe: "java", Lang: "java"}}}
	if err := os.WriteFile(shim(c), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	probeCmd = "/bin/true"
	for range 2 { // idempotent
		if err := apply(c); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(preloadPath)
	if string(b) != "/usr/lib/other.so\n"+shim(c)+"\n" {
		t.Fatalf("preload %q", b)
	}
	if conf, _ := os.ReadFile(confPath); !strings.Contains(string(conf), "java\tJAVA_TOOL_OPTIONS=") {
		t.Fatalf("conf %q", conf)
	}
	if err := remove(c); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(preloadPath); string(b) != "/usr/lib/other.so\n" {
		t.Fatalf("other preload entries lost: %q", b)
	}
	probeCmd = "/bin/false" // a process that fails to start takes the shim out again
	if err := apply(c); err == nil {
		t.Fatal("want an error")
	}
	if b, _ := os.ReadFile(preloadPath); strings.Contains(string(b), shim(c)) {
		t.Fatalf("shim left in after a failed probe: %q", b)
	}
}
