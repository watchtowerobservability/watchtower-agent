package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMachineIDStable(t *testing.T) {
	d := t.TempDir()
	mp := filepath.Join(d, "mid")
	os.WriteFile(mp, []byte("abc123\n"), 0o600)
	t.Setenv("WT_AGENT_MACHINE_ID_PATH", mp)
	a := machineID(d)
	if a != machineID(t.TempDir()) || len(a) != 32 || strings.Contains(a, "abc123") {
		t.Fatalf("host id not stable/hashed: %s", a)
	}
	t.Setenv("WT_AGENT_MACHINE_ID_PATH", filepath.Join(d, "missing"))
	t.Setenv("HOME", d)
	b := machineID(d)
	if b == "" || b != machineID(d) {
		t.Fatalf("persisted id unstable: %q", b)
	}
}

func TestStateDirFallback(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "file")
	os.WriteFile(f, nil, 0o600)
	t.Setenv("XDG_STATE_HOME", d)
	got := resolveStateDir(filepath.Join(f, "sub")) // under a regular file: unwritable
	if got != filepath.Join(d, "wt-agent") {
		t.Fatalf("fallback = %s", got)
	}
	if resolveStateDir(filepath.Join(d, "ok")) != filepath.Join(d, "ok") {
		t.Fatal("writable dir was replaced")
	}
}

func TestHealth(t *testing.T) {
	d := t.TempDir()
	now := time.Now()
	if checkHealth(d, time.Minute, now) == nil {
		t.Fatal("no file must be unhealthy")
	}
	h := NewHealthFile(d)
	h.Registered("a1")
	if checkHealth(d, time.Minute, now) == nil {
		t.Fatal("no export yet must be unhealthy")
	}
	h.Export(errors.New("boom"))
	h.Export(nil)
	if err := checkHealth(d, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	if checkHealth(d, time.Minute, time.Now().Add(2*time.Minute)) == nil {
		t.Fatal("stale export must be unhealthy")
	}
}

func TestBootstrapSQL(t *testing.T) {
	s := strings.Join(bootstrapSQL("deadbeef"), ";")
	for _, w := range []string{"CREATE ROLE wt_monitor LOGIN PASSWORD 'deadbeef'", "GRANT pg_monitor TO wt_monitor", "GRANT CONNECT ON DATABASE"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in %s", w, s)
		}
	}
	var out, errb strings.Builder
	if postgresCommand([]string{"bootstrap", "--print"}, &out, &errb) != 0 || !strings.Contains(out.String(), "pg_monitor") {
		t.Fatal(out.String(), errb.String())
	}
}
