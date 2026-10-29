package logs

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestMultilineJoinsStackTrace(t *testing.T) {
	log := filepath.Join(t.TempDir(), "m.log")
	appendTo(t, log, "2026-01-01 boom\n\tat a\n\tat b\n\tat c\n2026-01-01 next\n")
	var r sink.Recorder
	spec := TailSpec{Path: log, FromBeginning: true, Multiline: &Multiline{StartPattern: `^\d{4}-`, MaxLines: 3, MaxWait: "1s"}}
	tl, err := NewTailer([]TailSpec{spec}, LoadState(t.TempDir()), &r)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tl.Poll(now)
	// max_lines 3 cuts the trace; the fourth line starts a fresh pending record
	got := bodies(&r)
	if len(got) != 2 || got[0] != "2026-01-01 boom\n\tat a\n\tat b" || got[1] != "\tat c" {
		t.Fatalf("records: %q", got)
	}
	tl.Poll(now.Add(1500 * time.Millisecond)) // max_wait 1s, not the 2s default
	if got := bodies(&r); len(got) != 3 || got[2] != "2026-01-01 next" {
		t.Fatalf("max_wait flush: %q", got)
	}
}
