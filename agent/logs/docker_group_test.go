package logs

import (
	"strings"
	"testing"
	"time"
)

type groupOut struct {
	bodies []string
	last   time.Time
}

func newTestGroup(max int, clock *time.Time) (*lineGroup, *groupOut) {
	o := &groupOut{}
	g := newLineGroup(max, func(_, body string, _ time.Time) { o.bodies = append(o.bodies, body) },
		func(last time.Time) { o.last = last })
	g.now = func() time.Time { return *clock }
	return g, o
}

// The real ClickHouse shape that fed the merge failure loop: one record, not one row per frame.
func TestGroupJoinsClickHouseStackTrace(t *testing.T) {
	clock := time.Unix(1000, 0)
	g, o := newTestGroup(0, &clock)
	first := "2026.11.06 02:50:02 [ 659 ] {} <Error> MergeTreeBackgroundExecutor: Code: 241. Stack trace:"
	for _, l := range []string{first, "", "0. DB::Exception::Exception() @ 0x1", "6. ? @ 0x94a83", "(version 26.3.62.3 (official build))",
		"2026.11.06 02:50:03 [ 660 ] {} <Error> next failure"} {
		g.add("stderr", l, clock)
	}
	if len(o.bodies) != 1 || !strings.HasPrefix(o.bodies[0], first) || !strings.HasSuffix(o.bodies[0], "official build))") {
		t.Fatalf("got %d records: %q", len(o.bodies), o.bodies)
	}
	if Severity(o.bodies[0]) != "ERROR" {
		t.Fatalf("severity from the first line, got %s", Severity(o.bodies[0]))
	}
}

func TestGroupKeepsPlainLinesApartAndFlushesWhenQuiet(t *testing.T) {
	clock := time.Unix(1000, 0)
	g, o := newTestGroup(0, &clock)
	g.add("stdout", "one", clock)
	g.add("stdout", "two", clock)
	g.add("stderr", "  indented with nothing before it on this stream", clock)
	if len(o.bodies) != 1 || o.bodies[0] != "one" {
		t.Fatalf("%q", o.bodies)
	}
	g.flushQuiet()
	if len(o.bodies) != 1 {
		t.Fatalf("flushed early: %q", o.bodies)
	}
	clock = clock.Add(idleFlush)
	g.flushQuiet()
	if len(o.bodies) != 3 {
		t.Fatalf("not flushed after the quiet period: %q", o.bodies)
	}
}

func TestGroupCutsAtMaxLines(t *testing.T) {
	clock := time.Unix(1000, 0)
	g, o := newTestGroup(0, &clock)
	g.add("stderr", "head", clock)
	for range maxRecLines {
		g.add("stderr", "  frame", clock)
	}
	if len(o.bodies) != 1 || strings.Count(o.bodies[0], "\n") != maxRecLines-1 {
		t.Fatalf("records=%d", len(o.bodies))
	}
}

// Dropped records still advance the resume point, and the drop is reported, not silent.
func TestGroupRateCapDropsReportsAndAdvances(t *testing.T) {
	clock := time.Unix(1000, 0)
	g, o := newTestGroup(2, &clock)
	lastAt := clock
	for i := range 6 {
		lastAt = clock.Add(time.Duration(i) * time.Millisecond)
		g.add("stdout", "line", lastAt)
	}
	if len(o.bodies) != 2 { // 5 flushed, 2 kept, 3 dropped; the 6th is still pending
		t.Fatalf("%q", o.bodies)
	}
	if want := lastAt.Add(-time.Millisecond); !o.last.Equal(want) {
		t.Fatalf("resume point %v, want %v", o.last, want)
	}
	clock = clock.Add(time.Second)
	g.flushQuiet()
	if len(o.bodies) != 3 || !strings.Contains(o.bodies[2], "dropped 3 log records") || Severity(o.bodies[2]) != "WARN" {
		t.Fatalf("%q", o.bodies)
	}
}

func TestGroupStopFlushesEverything(t *testing.T) {
	clock := time.Unix(1000, 0)
	g, o := newTestGroup(0, &clock)
	stop := g.start()
	g.add("stdout", "last line before the stream closed", clock)
	stop()
	if len(o.bodies) != 1 {
		t.Fatalf("%q", o.bodies)
	}
}
