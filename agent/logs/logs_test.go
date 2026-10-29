package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func bodies(r *sink.Recorder) []string {
	var b []string
	for _, s := range r.Samples {
		b = append(b, s.Body)
	}
	return b
}

func TestFileTailResumesOffset(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	log := filepath.Join(dir, "app.log")
	appendTo(t, log, "one\ntwo\n")
	spec := []TailSpec{{Path: filepath.Join(dir, "*.log"), FromBeginning: true}}

	var r1 sink.Recorder
	t1, err := NewTailer(spec, LoadState(state), &r1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	t1.Poll(now)
	if got := bodies(&r1); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("first run: %v", got)
	}
	appendTo(t, log, "three\npartial")

	// a restart with the same state dir: only what is new, and never the half line
	var r2 sink.Recorder
	t2, _ := NewTailer(spec, LoadState(state), &r2)
	t2.Poll(now.Add(time.Second))
	if got := bodies(&r2); len(got) != 1 || got[0] != "three" {
		t.Fatalf("after restart: %v", got)
	}
	appendTo(t, log, " line\n")
	t2.Poll(now.Add(2 * time.Second))
	if got := bodies(&r2); len(got) != 2 || got[1] != "partial line" {
		t.Fatalf("completed line: %v", got)
	}
	// a rotated-away name keeps its place: rename, the inode (and offset) stay the same
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	t2.Poll(now.Add(3 * time.Second))
	if len(r2.Samples) != 2 {
		t.Fatalf("a rename must not re-read the file: %v", bodies(&r2))
	}
}

func TestFileTailMultiline(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "m.log")
	appendTo(t, log, "2026-01-01 start\n  at a\n  at b\n2026-01-01 next\n")
	var r sink.Recorder
	tl, err := NewTailer([]TailSpec{{Path: log, FromBeginning: true, MultilineStart: `^\d{4}-`}}, LoadState(t.TempDir()), &r)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tl.Poll(now)
	if got := bodies(&r); len(got) != 1 || got[0] != "2026-01-01 start\n  at a\n  at b" {
		t.Fatalf("joined record: %q", got)
	}
	tl.Poll(now.Add(5 * time.Second)) // idle: the last record is released
	if got := bodies(&r); len(got) != 2 || got[1] != "2026-01-01 next" {
		t.Fatalf("idle flush: %q", got)
	}
}

func TestSyslogRFC5424Parse(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	r, err := ParseSyslog(`<165>1 2026-10-28T10:15:00.003Z host1 myapp 1234 ID47 [exampleSDID@32473 iut="3" eventSource="App \"x\" \]"] BOMAn error occurred`, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Severity != "INFO" || r.Attrs["syslog.facility"] != "local4" || r.Attrs["syslog.hostname"] != "host1" ||
		r.Attrs["syslog.app"] != "myapp" || r.Attrs["process.pid"] != "1234" || r.Attrs["syslog.msgid"] != "ID47" {
		t.Fatalf("%+v", r)
	}
	if r.Body != "BOMAn error occurred" || r.At.Year() != 2026 || r.At.Hour() != 10 {
		t.Fatalf("body/time: %q %v", r.Body, r.At)
	}
	r, err = ParseSyslog("<11>1 - - - - - - boom\n", now)
	if err != nil || r.Severity != "ERROR" || r.Body != "boom" {
		t.Fatalf("nil values: %+v %v", r, err)
	}
	if _, err := ParseSyslog("<999>1 x", now); err == nil {
		t.Fatal("bad PRI accepted")
	}
}

func TestSyslogRFC3164Parse(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.Local)
	r, err := ParseSyslog("<34>Oct 11 22:14:15 mymachine su[230]: 'su root' failed for lonvick on /dev/pts/8", now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Severity != "ERROR" || r.Attrs["syslog.facility"] != "auth" || r.Attrs["syslog.hostname"] != "mymachine" ||
		r.Attrs["syslog.app"] != "su" || r.Attrs["process.pid"] != "230" {
		t.Fatalf("%+v", r)
	}
	if !strings.HasPrefix(r.Body, "'su root' failed") || r.At.Month() != time.October || r.At.Day() != 11 || r.At.Year() != 2026 {
		t.Fatalf("body/time: %q %v", r.Body, r.At)
	}
	r, _ = ParseSyslog("<13>no header at all", now)
	if r.Body != "no header at all" {
		t.Fatalf("headerless message: %q", r.Body)
	}
	if stripOctetCount("17 <34>1 - - - - - -") != "<34>1 - - - - - -" {
		t.Fatal("octet counting")
	}
}

func TestJournaldJSONParse(t *testing.T) {
	b, err := os.ReadFile("testdata/journal.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	r, err := ParseJournalLine([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	if r.Severity != "ERROR" || r.Body != "Failed to start Foo." || r.Attrs["systemd.unit"] != "foo.service" ||
		r.Attrs["syslog.hostname"] != "web1" || r.At.UnixMicro() != 1761646500123456 {
		t.Fatalf("%+v", r)
	}
	r, err = ParseJournalLine([]byte(lines[1]))
	if err != nil || r.Body != "hi" || r.Severity != "DEBUG" {
		t.Fatalf("byte-array message: %+v %v", r, err)
	}
}

func TestParseEventXML(t *testing.T) {
	r, err := ParseEventXML(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
		<Provider Name="Service Control Manager"/><EventID>7036</EventID><Level>3</Level>
		<TimeCreated SystemTime="2026-10-28T10:00:00.123456700Z"/><Channel>System</Channel><Computer>PC1</Computer></System>
		<EventData><Data Name="param1">Print Spooler</Data><Data>stopped</Data></EventData></Event>`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Severity != "WARN" || r.Attrs["windows.event.id"] != "7036" || r.Body != "Service Control Manager event 7036: param1=Print Spooler; stopped" {
		t.Fatalf("%+v", r)
	}
}
