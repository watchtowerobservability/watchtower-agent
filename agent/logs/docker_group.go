package logs

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// continuation matches a line that belongs to the record before it: indented or numbered stack
// frames, Java's "at"/"Caused by", ClickHouse's closing "(version ...)", and blank lines.
// shortcut: a guess with no per-container config, and unindented Go panic frames still split; add a
// per-container start_pattern if a real workload is grouped wrongly.
var continuation = regexp.MustCompile(`^(\s|$|\d+\. |at |Caused by:|\.\.\. \d+ more|\(version )`)

type groupRec struct {
	lines       []string
	bytes       int
	start, last time.Time
	seen        time.Time // wall clock of the newest line, for the quiet flush
}

// lineGroup joins one container's lines into records, per stream, and optionally caps the records
// per second. A noisy container cannot flood the pipeline when a cap is set.
type lineGroup struct {
	mu      sync.Mutex
	pend    map[string]*groupRec
	max     int // records per second, 0 = no cap
	now     func() time.Time
	sec     int64
	n       int
	dropped int
	out     func(stream, body string, at time.Time)
	mark    func(last time.Time) // a record's lines are handled, emitted or dropped
}

func newLineGroup(max int, out func(stream, body string, at time.Time), mark func(time.Time)) *lineGroup {
	return &lineGroup{pend: map[string]*groupRec{}, max: max, now: time.Now, out: out, mark: mark}
}

func (g *lineGroup) add(stream, line string, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.pend[stream]
	if p != nil && continuation.MatchString(line) && len(p.lines) < maxRecLines && p.bytes < maxRecBytes {
		p.lines = append(p.lines, line)
		p.bytes += len(line) + 1
		p.last, p.seen = at, g.now()
		return
	}
	g.flush(stream)
	g.pend[stream] = &groupRec{lines: []string{line}, bytes: len(line) + 1, start: at, last: at, seen: g.now()}
}

// flush hands over a stream's pending record. The caller holds mu.
func (g *lineGroup) flush(stream string) {
	p := g.pend[stream]
	if p == nil {
		return
	}
	delete(g.pend, stream)
	g.report()
	if g.max > 0 && g.n >= g.max {
		g.dropped++
	} else {
		g.n++
		g.out(stream, strings.Join(p.lines, "\n"), p.start)
	}
	g.mark(p.last)
}

// report starts a new one-second window and says what the last ones dropped. The caller holds mu.
func (g *lineGroup) report() {
	now := g.now()
	if now.Unix() == g.sec {
		return
	}
	g.sec, g.n = now.Unix(), 0
	if g.dropped > 0 {
		g.out("stderr", fmt.Sprintf("WARN wt-agent dropped %d log records from this container (limit %d per second)", g.dropped, g.max), now)
		g.dropped = 0
	}
}

// flushQuiet flushes records with no new line for idleFlush, and any pending drop report.
func (g *lineGroup) flushQuiet() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for stream, p := range g.pend {
		if now.Sub(p.seen) >= idleFlush {
			g.flush(stream)
		}
	}
	g.report()
}

// start runs the quiet flush until the returned stop, which flushes everything left.
func (g *lineGroup) start() (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				g.flushQuiet()
			}
		}
	}()
	return func() {
		close(done)
		<-finished
		g.mu.Lock()
		defer g.mu.Unlock()
		for stream := range g.pend {
			g.flush(stream)
		}
		g.sec = 0 // the final report does not wait for the next second
		g.report()
	}
}
