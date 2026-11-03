package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplainListsModulesAndRedacts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WT_EXPLAIN_PW", "s3cr3t-value")
	cfg := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(cfg, []byte(`endpoint: https://gw.example.com:4318
state_dir: `+dir+`
modules:
  postgres:
    dsn: "postgres://wt:${env:WT_EXPLAIN_PW}@db.internal:5432/app?sslmode=require"
  mysql:
    dsn: "user=wt password=hunter2 host=db2"
  logs:
    files: [{path: /var/log/app.log}]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(dir, "remote.yaml")
	if err := os.WriteFile(remote, []byte("modules:\n  logs: {enabled: false}\n  gpu: {nvidia_smi_path: /tmp/evil}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := explain(context.Background(), cfg, remote, &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"exports to: https://gw.example.com:4318", "module postgres: starts", "dsn = postgres://<redacted>@db.internal:5432/app?<redacted>",
		"secret references (env): resolved (values redacted)", "module logs: disabled", "files[0].path = /var/log/app.log", "remote config refused", "password=<redacted>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3cr3t-value") || strings.Contains(out, "hunter2") {
		t.Fatalf("a secret leaked:\n%s", out)
	}
}
