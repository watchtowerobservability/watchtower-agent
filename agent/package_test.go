package main

import (
	"os"
	"strings"
	"testing"
	"github.com/watchtowerobservability/watchtower-agent/internal/repofile"

	"gopkg.in/yaml.v3"
)

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(repofile.Path(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestPackagingFiles pins what the installers promise: nfpm ships the unit and a config that is
// kept on upgrade, the unit runs unprivileged, and install.sh verifies a sha256 and does not
// pipe a download into a shell.
func TestPackagingFiles(t *testing.T) {
	var n struct {
		Name     string `yaml:"name"`
		Contents []struct {
			Dst  string `yaml:"dst"`
			Type string `yaml:"type"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal([]byte(read(t, "infra/agent/nfpm.yaml")), &n); err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	for _, c := range n.Contents {
		have[c.Dst] = c.Type
	}
	for _, dst := range []string{"/usr/bin/wt-agent", "/usr/lib/systemd/system/wt-agent.service"} {
		if _, ok := have[dst]; !ok {
			t.Errorf("nfpm.yaml does not ship %s", dst)
		}
	}
	if have["/etc/wt-agent/agent.yaml"] != "config|noreplace" {
		t.Error("the config must survive an upgrade")
	}
	unit := read(t, "infra/agent/wt-agent.service")
	for _, want := range []string{"User=wt-agent", "NoNewPrivileges=true", "ProtectSystem=strict"} {
		if !strings.Contains(unit, want) {
			t.Errorf("wt-agent.service lacks %s", want)
		}
	}
	sh := read(t, "infra/agent/install.sh")
	if !strings.Contains(sh, "sha256 mismatch") || strings.Contains(sh, "| sh") || strings.Contains(sh, "| bash") {
		t.Error("install.sh must verify a sha256 and never pipe into a shell")
	}
	var cfg LocalConfig
	if err := yaml.Unmarshal([]byte(read(t, "infra/agent/agent.example.yaml")), &cfg); err != nil || cfg.TokenFile == "" {
		t.Errorf("agent.example.yaml must parse and point at a token_file: %v", err)
	}
}
