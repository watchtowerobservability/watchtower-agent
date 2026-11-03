package redact

import "strings"

// Actions a project can pick for a PII kind.
const (
	ActionReplace = "replace" // [REDACTED:<kind>]
	ActionHash    = "hash"    // [HASH:<kind>:<salted sha-256 prefix>], stable per value
	ActionPartial = "partial" // ****1234, last four characters kept
)

// PIIKinds are the pattern kinds a project may switch on at the gateway (PIIPatterns' order).
var PIIKinds = func() []string {
	out := make([]string, len(PIIPatterns))
	for i, p := range PIIPatterns {
		out[i] = p.Kind
	}
	return out
}()

// Limits of a detector's optional fields (the API enforces the same).
const (
	MaxKeywords   = 10
	MaxKeywordLen = 64
)

// Detector turns on one PII kind for a project with an action. Keywords (optional) require one
// of them, case-insensitive, within 64 bytes before a match (Datadog-style keyword proximity).
// Services (optional globs) and SamplePercent (1-99; 0 or 100 = every record) scope the detector
// to a scanning group; the gateway applies them per record.
type Detector struct {
	Kind          string   `json:"kind"`
	Action        string   `json:"action"`
	Keywords      []string `json:"keywords,omitempty"`
	Services      []string `json:"services,omitempty"`
	SamplePercent int      `json:"sample_percent,omitempty"`
}

// Valid reports whether d names a known kind and action and its optional fields are in range.
func (d Detector) Valid() bool {
	k := false
	for _, p := range PIIKinds {
		k = k || p == d.Kind
	}
	if len(d.Keywords) > MaxKeywords || d.SamplePercent < 0 || d.SamplePercent > 100 {
		return false
	}
	for _, w := range d.Keywords {
		if w == "" || len(w) > MaxKeywordLen {
			return false
		}
	}
	return k && (d.Action == ActionReplace || d.Action == ActionHash || d.Action == ActionPartial)
}

// Scoped reports whether d applies only to some services or a sample of records.
func (d Detector) Scoped() bool {
	return len(d.Services) > 0 || (d.SamplePercent > 0 && d.SamplePercent < 100)
}

// NewPII builds a Redactor with only the selected kinds (invalid detectors are skipped), each with
// its checksum and keyword rule. salt separates hash outputs per project.
func NewPII(dets []Detector, salt []byte) *Redactor {
	r := New(Standard, nil, nil)
	r.salt, r.pats = salt, nil
	sel := map[string]Detector{}
	for _, d := range dets {
		if d.Valid() {
			sel[d.Kind] = d
		}
	}
	for _, p := range piiCompiled {
		d, ok := sel[p.kind]
		if !ok {
			continue
		}
		p.action = d.Action
		for _, w := range d.Keywords {
			p.keywords = append(p.keywords, strings.ToLower(w))
		}
		r.pats = append(r.pats, p)
	}
	return r
}
