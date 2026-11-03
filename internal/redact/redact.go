// Package redact masks secrets and PII in tool results before they are stored or sent to a model.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
)

type compiled struct {
	kind     string
	action   string // "" = replace
	re       *regexp.Regexp
	check    func(string) bool // checksum a match must pass (nil = none)
	keywords []string          // lower-case; one must precede the match (nil = no proximity rule)
}

// Redactor is immutable and safe for concurrent use.
type Redactor struct {
	pats    []compiled
	keyRe   *regexp.Regexp
	blocked []*regexp.Regexp
	salt    []byte // per-project salt of the hash action
}

// New builds a Redactor. Invalid custom patterns or blocked globs are skipped (they were
// validated when saved); `*` in a blocked entry matches any characters.
func New(level Level, custom []Pattern, blocked []string) *Redactor {
	r := &Redactor{keyRe: regexp.MustCompile(sensitiveKeys)}
	add := func(p Pattern) {
		if p.Strict && level != Strict {
			return
		}
		if re, err := regexp.Compile(p.Regex); err == nil {
			c := compiled{kind: p.Kind, re: re}
			if p.Kind == "card" {
				c.check = Luhn // digits that fail the checksum are not a card number
			}
			r.pats = append(r.pats, c)
		}
	}
	for _, p := range Defaults {
		add(p)
	}
	for _, p := range custom {
		if p.Kind == "" {
			p.Kind = "custom"
		}
		p.Strict = false
		add(p)
	}
	for _, b := range blocked {
		parts := strings.Split(strings.ToLower(b), "*")
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		if re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$"); err == nil {
			r.blocked = append(r.blocked, re)
		}
	}
	return r
}

// Text masks every pattern match in s with [REDACTED:<kind>] (or the pattern's action). A match
// whose checksum fails, or that lacks a required keyword before it, is kept.
func (r *Redactor) Text(s string) string {
	for _, p := range r.pats {
		locs := p.re.FindAllStringIndex(s, -1)
		var b strings.Builder
		last := 0
		for _, l := range locs {
			if m := s[l[0]:l[1]]; p.keeps(s, l[0], m) {
				b.WriteString(s[last:l[0]])
				b.WriteString(r.mask(p, m))
				last = l[1]
			}
		}
		if b.Len() > 0 {
			b.WriteString(s[last:])
			s = b.String()
		}
	}
	return s
}

// mask is the replacement for one match under the pattern's action.
func (r *Redactor) mask(p compiled, m string) string {
	switch p.action {
	case ActionHash:
		h := sha256.Sum256(append(append([]byte{}, r.salt...), m...))
		return "[HASH:" + p.kind + ":" + hex.EncodeToString(h[:8]) + "]"
	case ActionPartial:
		if t := []rune(m); len(t) > 4 {
			return "****" + string(t[len(t)-4:])
		}
	}
	return "[REDACTED:" + p.kind + "]"
}

// Luhn reports whether s (digits, spaces and dashes only) is 13 to 19 digits with a valid Luhn
// checksum. testdata/redact_vectors.json pins it against the Rust implementation.
func Luhn(s string) bool {
	n, sum, dbl := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if dbl {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum, dbl, n = sum+d, !dbl, n+1
	}
	return n >= 13 && n <= 19 && sum%10 == 0
}

// Glob matches s against pat, where `*` matches any run of characters (case-insensitive).
func Glob(pat, s string) bool {
	pat, s = strings.ToLower(pat), strings.ToLower(s)
	p, t, star, mark := 0, 0, -1, 0
	for t < len(s) {
		switch {
		case p < len(pat) && pat[p] == '*':
			star, mark, p = p, t, p+1
		case p < len(pat) && pat[p] == s[t]:
			p, t = p+1, t+1
		case star >= 0:
			mark++
			p, t = star+1, mark
		default:
			return false
		}
	}
	return strings.Trim(pat[p:], "*") == ""
}

// JSON walks raw, drops blocked fields and masks string values. Non-JSON input is treated as text.
func (r *Redactor) JSON(raw []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte(r.Text(string(raw)))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep '<' intact; delimiter escaping is the wrapper's job
	if err := enc.Encode(r.walk(v, "")); err != nil {
		return []byte(r.Text(string(raw)))
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func (r *Redactor) isBlocked(path, key string) bool {
	path, key = strings.ToLower(path), strings.ToLower(key)
	for _, b := range r.blocked {
		if b.MatchString(path) || b.MatchString(key) {
			return true
		}
	}
	return false
}

func (r *Redactor) walk(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if r.isBlocked(p, k) {
				continue
			}
			if _, ok := val.(string); ok && r.keyRe.MatchString(k) {
				out[k] = "[REDACTED:key]"
				continue
			}
			out[k] = r.walk(val, p)
		}
		return out
	case []any:
		for i := range t {
			t[i] = r.walk(t[i], path)
		}
		return t
	case string:
		return r.Text(t)
	default:
		return v
	}
}
