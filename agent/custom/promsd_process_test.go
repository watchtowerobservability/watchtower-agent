package custom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessSD(t *testing.T) {
	root := t.TempDir()
	write := func(pid, name, body string) {
		_ = os.MkdirAll(filepath.Join(root, pid), 0o755)
		if err := os.WriteFile(filepath.Join(root, pid, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("42", "cmdline", "java\x00-jar\x00app.jar\x00")
	write("42", "status", "Name:\tjava\nUid:\t1000\t1000\t1000\t1000\n")
	write("42", "cgroup", "0::/docker/"+strings.Repeat("ab", 32)+"\n")
	write("7", "cmdline", "") // kernel thread
	_ = os.Mkdir(filepath.Join(root, "self"), 0o755)
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()
	if _, err := (SDConfig{Type: "process"}).processSD(context.Background(), nil); err == nil {
		t.Fatal("port not required")
	}
	got, err := SDConfig{Type: "process", Port: 9404}.processSD(context.Background(), nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	l := got[0].Labels
	if got[0].URL != "http://127.0.0.1:9404/metrics" || l["__process_pid__"] != "42" || l["__meta_process_commandline"] != "java -jar app.jar" ||
		l["__meta_process_uid"] != "1000" || len(l["__meta_process_container_id"]) != 64 {
		t.Fatal(got[0])
	}
}
