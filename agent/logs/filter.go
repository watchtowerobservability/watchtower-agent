package logs

import (
	"fmt"
	"regexp"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MatchRules drops log records on the host, before they are batched or sent:
// `include_at_match` keeps only records matching at least one of the regexes, `exclude_at_match`
// drops records matching any of them (exclusion wins). It sits on the global logs config, on a
// file input and on the docker input; the regexes see the whole record body (a joined multiline
// record included). Empty: everything passes.
type MatchRules struct {
	Include []string `json:"include_at_match"`
	Exclude []string `json:"exclude_at_match"`
}

type matchSink struct {
	sink.Sink
	inc, exc []*regexp.Regexp
}

func compileAll(list []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(list))
	for _, p := range list {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("match rule %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Wrap returns out with the rules applied to its log records (out itself when there are none).
func (m MatchRules) Wrap(out sink.Sink) (sink.Sink, error) {
	if len(m.Include) == 0 && len(m.Exclude) == 0 {
		return out, nil
	}
	inc, err := compileAll(m.Include)
	if err != nil {
		return nil, err
	}
	exc, err := compileAll(m.Exclude)
	if err != nil {
		return nil, err
	}
	return &matchSink{Sink: out, inc: inc, exc: exc}, nil
}

func (s *matchSink) keep(body string) bool {
	for _, re := range s.exc {
		if re.MatchString(body) {
			return false
		}
	}
	if len(s.inc) == 0 {
		return true
	}
	for _, re := range s.inc {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

// Log forwards the record unless the rules drop it.
func (s *matchSink) Log(severity, body string, attrs map[string]string, at time.Time) {
	if s.keep(body) {
		s.Sink.Log(severity, body, attrs, at)
	}
}
