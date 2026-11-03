package wtapi

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// TestGeneratedClientUpToDate regenerates the client from apps/web/openapi.json with the pinned
// oapi-codegen and fails when the committed files differ (run `go generate ./wtapi`).
func TestGeneratedClientUpToDate(t *testing.T) {
	src, err := os.ReadFile("gen.go")
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`(github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v\d+\.\d+\.\d+) `).FindSubmatch(src)
	if pin == nil {
		t.Fatal("the go:generate directive must pin an oapi-codegen release")
	}
	tmp := t.TempDir()
	spec := filepath.Join(tmp, "openapi30.gen.json")
	out := filepath.Join(tmp, "client.gen.go")
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("go", append([]string{"run"}, args...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("cannot regenerate (offline?): %v\n%s", err, b)
		}
	}
	// cfg.yaml names its output file, which would win over -o: use a copy without it.
	cfg, err := os.ReadFile("cfg.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfgCopy := filepath.Join(tmp, "cfg.yaml")
	if err := os.WriteFile(cfgCopy, regexp.MustCompile(`(?m)^output:.*\n`).ReplaceAll(cfg, nil), 0o644); err != nil {
		t.Fatal(err)
	}
	run("./prep", "../../sdks/api-schema/openapi.json", spec)
	run(string(pin[1]), "-config", cfgCopy, "-o", out, spec)
	for got, want := range map[string]string{spec: "openapi30.gen.json", out: "client.gen.go"} {
		a, _ := os.ReadFile(got)
		b, err := os.ReadFile(want)
		if err != nil || !bytes.Equal(a, b) {
			t.Errorf("%s is stale: run `go generate ./wtapi`", want)
		}
	}
}
