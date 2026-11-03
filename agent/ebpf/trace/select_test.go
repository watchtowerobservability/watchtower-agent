package trace

import (
	"testing"
	"time"
)

func TestSelection(t *testing.T) {
	procs := map[uint32]ProcInfo{
		1: {Exe: "/usr/bin/node", Name: "node", Ports: []int{3000}},
		2: {Exe: "/usr/lib/jvm/bin/java", Name: "java", Cmdline: []byte("java\x00-javaagent:/otel/opentelemetry-javaagent.jar")},
		3: {Exe: "/usr/sbin/sshd", Name: "sshd", Ports: []int{22}},
		4: {Exe: "/app/api", Name: "api", Environ: []byte("PATH=/bin\x00OTEL_EXPORTER_OTLP_ENDPOINT=http://x")},
	}
	read := func(pid uint32) (ProcInfo, bool) { p, ok := procs[pid]; return p, ok }
	s := Config{Exclude: []Selector{{Port: 22}}}.Selection(read)
	now := time.Now()
	for pid, want := range map[uint32]bool{1: true, 2: false, 3: false, 4: false, 9: true} {
		if got := s.Keep(pid, now); got != want {
			t.Errorf("pid %d keep = %v, want %v", pid, got, want)
		}
	}
	off := false
	s = Config{Include: []Selector{{ExePath: "*/java"}, {Name: "api"}}, SkipInstrumented: &off}.Selection(read)
	if s.Keep(1, now) || !s.Keep(2, now) || !s.Keep(4, now) {
		t.Fatal("include by exe glob or name")
	}
	if s.Skipped() != 1 {
		t.Fatalf("skipped %d", s.Skipped())
	}
}
