package custom

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
)

func TestCollapsedToPprof(t *testing.T) {
	gz, err := collapsedToPprof(strings.NewReader("main;work;leaf 12\nmain;other 3\nnot a stack\n"), time.Second, "cpu")
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Parse(bytes.NewReader(gz))
	if err != nil || len(p.Sample) != 2 || p.Sample[0].Value[0] != 12 {
		t.Fatal(p, err)
	}
	if got := p.Sample[0].Location[0].Line[0].Function.Name; got != "leaf" {
		t.Fatal(got)
	}
}

func TestJavaProcsAndMainClass(t *testing.T) {
	root := t.TempDir()
	write := func(pid, cmd string) {
		_ = os.MkdirAll(filepath.Join(root, pid), 0o755)
		if err := os.WriteFile(filepath.Join(root, pid, "cmdline"), []byte(strings.ReplaceAll(cmd, " ", "\x00")+"\x00"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "/usr/bin/java -Xmx1g -jar /srv/orders.jar")
	write("11", "/usr/bin/java -cp a.jar com.acme.Other")
	write("12", "/usr/bin/python orders.jar")
	got := javaProcs(root, regexp.MustCompile("orders"))
	if len(got) != 1 || got[10] != "orders" {
		t.Fatal(got)
	}
	if mainClass([]string{"java", "-cp", "a.jar", "com.acme.Main"}) != "com.acme.Main" {
		t.Fatal("main class")
	}
}

func TestAsyncProfilerRefusesLooseConfig(t *testing.T) {
	for _, c := range []string{`{"binary":"asprof","match":"x"}`, `{"binary":"/a"}`, `{"binary":"/a","match":"x","event":"cpu;rm"}`, `{"binary":"/a","match":"x","interval":"1s"}`} {
		if err := AsyncProfile(context.Background(), json.RawMessage(c), nil); err == nil {
			t.Fatal(c)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := AsyncProfile(ctx, nil, nil); err != nil { // inert without a binary
		t.Fatal(err)
	}
}
