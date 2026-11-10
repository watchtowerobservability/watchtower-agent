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

func TestAutoMultilineDetectsTimestampStarts(t *testing.T) {
	log := filepath.Join(t.TempDir(), "auto.log")
	var s string
	for i := 1; i <= 5; i++ {
		s += "2026-01-01 10:00:0" + string(rune('0'+i)) + " ERROR boom\n\tat a.b(C.java:1)\n\tat d.e(F.java:2)\n"
	}
	appendTo(t, log, s+"2026-01-01 10:00:09 INFO last\n")
	var r sink.Recorder
	spec := TailSpec{Path: log, FromBeginning: true, Multiline: &Multiline{Auto: true}}
	tl, err := NewTailer([]TailSpec{spec}, LoadState(t.TempDir()), &r)
	if err != nil {
		t.Fatal(err)
	}
	tl.Poll(time.Now())
	got := bodies(&r)
	if len(got) != 5 || got[0] != "2026-01-01 10:00:01 ERROR boom\n\tat a.b(C.java:1)\n\tat d.e(F.java:2)" {
		t.Fatalf("records: %q", got)
	}
}

func TestDetectStartNeedsEnoughPlainLines(t *testing.T) {
	if detectStart([]string{"2026-01-01 10:00 a", "\tat x"}) != nil {
		t.Fatal("two lines are not a sample")
	}
	if detectStart([]string{"a", "b", "c", "d", "e", "f"}) != nil {
		t.Fatal("free text matches no candidate")
	}
	if detectStart([]string{"Jan  2 10:00:00 a", "Jan  2 10:00:01 b", "Jan  2 10:00:02 c", "Jan  2 10:00:03 d", "x"}) == nil {
		t.Fatal("80 percent of the plain lines match the syslog shape")
	}
}

func TestMatchRulesIncludeExclude(t *testing.T) {
	log := filepath.Join(t.TempDir(), "m.log")
	appendTo(t, log, "keep one\nDEBUG noisy\nkeep health-check\nother\n")
	var r sink.Recorder
	spec := TailSpec{Path: log, FromBeginning: true, MatchRules: MatchRules{
		Include: []string{`^keep`}, Exclude: []string{`health-check`}}}
	tl, err := NewTailer([]TailSpec{spec}, LoadState(t.TempDir()), &r)
	if err != nil {
		t.Fatal(err)
	}
	tl.Poll(time.Now())
	if got := bodies(&r); len(got) != 1 || got[0] != "keep one" {
		t.Fatalf("records: %q", got)
	}
	if _, err := NewTailer([]TailSpec{{Path: log, MatchRules: MatchRules{Exclude: []string{"("}}}}, LoadState(t.TempDir()), &r); err == nil {
		t.Fatal("a bad regex must be rejected")
	}
}
