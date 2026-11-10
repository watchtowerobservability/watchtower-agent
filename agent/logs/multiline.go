package logs

import (
	"regexp"
	"time"
)

// Multiline joins the lines of one record (a stack trace) per file input:
// `multiline: {start_pattern, max_lines, max_wait}`. A line matching StartPattern begins a new
// record. It supersedes the older flat `multiline_start` key, which still works.
type Multiline struct {
	StartPattern string `json:"start_pattern"`
	MaxLines     int    `json:"max_lines"` // default 500
	MaxWait      string `json:"max_wait"`  // default 2s: a pending record is flushed after this much quiet
	// Auto picks the start pattern itself (timestamp shapes, log levels, JSON objects) from the
	// first lines of each file when no start_pattern is set; see detectStart.
	Auto bool `json:"auto"`
}

func (s TailSpec) resolveStart() string {
	p, _, _ := s.resolve()
	return p
}

// startCandidates are the record-start shapes auto detection tries, most specific first.
var startCandidates = []*regexp.Regexp{
	regexp.MustCompile(`^\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}`),
	regexp.MustCompile(`^\[?\d{4}/\d{2}/\d{2} \d{2}:\d{2}`),
	regexp.MustCompile(`^\d{2}/\d{2}/\d{4}[ :]\d{2}:\d{2}`),
	regexp.MustCompile(`^[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`^\d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b`),
	regexp.MustCompile(`^\{`),
}

const detectMinLines = 5

// detectStart returns the candidate that matches at least 80 percent of the non-indented lines
// (indented lines, such as "\tat Foo.bar" or "    File ...", are continuations by nature), or nil
// when there are fewer than detectMinLines non-indented lines or no candidate fits. A pattern is
// only worth enabling if some line is a continuation of it: free-form single-line logs that all
// start the same way keep working either way, so detection does not insist on seeing a trace.
func detectStart(lines []string) *regexp.Regexp {
	var head []string
	for _, l := range lines {
		if l != "" && l[0] != ' ' && l[0] != '\t' {
			head = append(head, l)
		}
	}
	if len(head) < detectMinLines {
		return nil
	}
	for _, re := range startCandidates {
		n := 0
		for _, l := range head {
			if re.MatchString(l) {
				n++
			}
		}
		if n*5 >= len(head)*4 {
			return re
		}
	}
	return nil
}

// resolve returns the pattern, line cap and quiet period for a spec, with defaults applied.
func (s TailSpec) resolve() (pattern string, maxLines int, maxWait time.Duration) {
	pattern, maxLines, maxWait = s.MultilineStart, maxRecLines, idleFlush
	if m := s.Multiline; m != nil {
		if m.StartPattern != "" {
			pattern = m.StartPattern
		}
		if m.MaxLines > 0 {
			maxLines = min(m.MaxLines, maxRecLines*10)
		}
		if d, err := time.ParseDuration(m.MaxWait); err == nil && d > 0 {
			maxWait = d
		}
	}
	return pattern, maxLines, maxWait
}
