package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestTailStateOnlyWhenChangedAndPruned(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	log := filepath.Join(dir, "a.log")
	appendTo(t, log, "x\n")
	var r sink.Recorder
	tl, _ := NewTailer([]TailSpec{{Path: log, FromBeginning: true}}, LoadState(state), &r)
	now := time.Now()
	tl.Poll(now)
	file := filepath.Join(state, "tail-offsets.json")
	old := now.Add(-time.Hour)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	tl.Poll(now.Add(time.Second))
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Before(now.Add(-30 * time.Minute)) {
		t.Fatal("an unchanged state must not be rewritten")
	}
	if err := os.Remove(log); err != nil {
		t.Fatal(err)
	}
	tl.Poll(now.Add(25 * time.Hour))
	if got := LoadState(state); len(got.Off) != 0 {
		t.Fatalf("entries of files gone for 24h are pruned: %v", got.Off)
	}
}

func TestTailReusedInodeStartsAtZero(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	log := filepath.Join(dir, "a.log")
	appendTo(t, log, "one\ntwo\nthree\n")
	var r1 sink.Recorder
	t1, _ := NewTailer([]TailSpec{{Path: log, FromBeginning: true}}, LoadState(state), &r1)
	t1.Poll(time.Now())
	// the same inode now holds a smaller, different file (truncate and rewrite)
	if err := os.WriteFile(log, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var r2 sink.Recorder
	t2, _ := NewTailer([]TailSpec{{Path: log}}, LoadState(state), &r2)
	t2.Poll(time.Now())
	if got := bodies(&r2); len(got) != 1 || got[0] != "new" {
		t.Fatalf("a smaller file under a known identity is read from 0: %v", got)
	}
}

func TestTailMultilineByteCapAndRuneTruncation(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "m.log")
	appendTo(t, log, "START\n")
	big := strings.Repeat("eé", 20<<10) // 2-byte runes, 60 KiB per line
	for range 10 {
		appendTo(t, log, big+"\n")
	}
	var r sink.Recorder
	tl, _ := NewTailer([]TailSpec{{Path: log, FromBeginning: true, MultilineStart: "^START"}}, LoadState(t.TempDir()), &r)
	tl.Poll(time.Now())
	if len(r.Samples) == 0 {
		t.Fatal("the byte cap must release the record")
	}
	for _, s := range r.Samples {
		if len(s.Body) > maxRecBytes+maxLine {
			t.Fatalf("record of %d bytes exceeds the cap", len(s.Body))
		}
	}
	if cut := sink.Truncate("aé", 2); cut != "a" {
		t.Fatalf("truncate must stay on a rune boundary: %q", cut)
	}
}
