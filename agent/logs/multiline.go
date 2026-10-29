package logs

import "time"

// Multiline joins the lines of one record (a stack trace) per file input:
// `multiline: {start_pattern, max_lines, max_wait}`. A line matching StartPattern begins a new
// record. It supersedes the older flat `multiline_start` key, which still works.
type Multiline struct {
	StartPattern string `json:"start_pattern"`
	MaxLines     int    `json:"max_lines"` // default 500
	MaxWait      string `json:"max_wait"`  // default 2s: a pending record is flushed after this much quiet
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
