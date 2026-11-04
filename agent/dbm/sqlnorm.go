package dbm

// Canonical SQL normalization and statement hash, ported from services/worker/src/sqlnorm.rs
// (spec: docs/product/instrumentation/sql-normalization.md, vectors:
// testdata/sql_normalize_vectors.json). Agent hashes must equal span hashes byte for byte.

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeebo/xxh3"
)

const (
	maxStatementBytes = 8 << 10
	maxDollarTag      = 32
)

// isAlnum is Rust char::is_alphanumeric: Unicode Alphabetic or any Number category.
func isAlnum(r rune) bool {
	return unicode.In(r, unicode.Letter, unicode.Nl, unicode.Other_Alphabetic, unicode.Number)
}

func isWordRune(r rune) bool { return isAlnum(r) || r == '_' || r == '$' }

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// NormalizeSQL is the canonical normalization: literals become `?`, comments go, whitespace
// collapses and `IN (?, ?)` becomes `IN (?+)`. pg is true for postgresql, cockroachdb, redshift.
func NormalizeSQL(stmt string, pg bool) string {
	if len(stmt) > maxStatementBytes {
		end := maxStatementBytes
		for end > 0 && !utf8.RuneStart(stmt[end]) {
			end--
		}
		stmt = stmt[:end]
	}
	cs := []rune(strings.ToValidUTF8(stmt, "�"))
	var out strings.Builder
	space := false
	for i := 0; i < len(cs); {
		c := cs[i]
		var next rune = -1
		if i+1 < len(cs) {
			next = cs[i+1]
		}
		switch {
		case unicode.Is(unicode.White_Space, c):
			space = true
			i++
		case c == '/' && next == '*':
			depth := 1
			i += 2
			for i < len(cs) && depth > 0 {
				switch {
				case cs[i] == '/' && i+1 < len(cs) && cs[i+1] == '*':
					depth, i = depth+1, i+2
				case cs[i] == '*' && i+1 < len(cs) && cs[i+1] == '/':
					depth, i = depth-1, i+2
				default:
					i++
				}
			}
			space = true
		case c == '-' && next == '-' || c == '#' && !pg:
			for i < len(cs) && cs[i] != '\n' {
				i++
			}
			space = true
		default:
			if space && out.Len() > 0 {
				out.WriteByte(' ')
			}
			space = false
			i = sqlToken(cs, i, pg, &out)
		}
	}
	return collapseIn(out.String())
}

// HashSQL is NormalizeSQL plus the canonical hash.
func HashSQL(stmt string, pg bool) (string, string) {
	n := NormalizeSQL(stmt, pg)
	return n, Hash(n)
}

// dollarQuoted returns the index past the `$tag$ ... $tag$` string opening at i, or -1.
func dollarQuoted(cs []rune, i int) int {
	tagLen := -1
	for j := i + 1; j < len(cs) && j <= i+1+maxDollarTag; j++ {
		if cs[j] == '$' {
			tagLen = j - i - 1
			break
		}
	}
	if tagLen < 0 {
		return -1
	}
	tag := cs[i : i+tagLen+2]
	for _, r := range tag[1 : tagLen+1] {
		if !isAlnum(r) && r != '_' {
			return -1
		}
	}
	if tagLen > 0 && isDigit(tag[1]) {
		return -1
	}
	for j := i + len(tag); j+len(tag) <= len(cs); j++ {
		if slices.Equal(cs[j:j+len(tag)], tag) {
			return j + len(tag)
		}
	}
	return len(cs)
}

func sqlToken(cs []rune, i int, pg bool, out *strings.Builder) int {
	c := cs[i]
	if c == '\'' {
		i++
		for i < len(cs) {
			if cs[i] == '\'' {
				if i+1 >= len(cs) || cs[i+1] != '\'' {
					break
				}
				i++
			}
			i++
		}
		out.WriteByte('?')
		if i < len(cs) && cs[i-1] == '\\' {
			return len(cs) // a MySQL escape may have closed nothing: mask the rest
		}
		return i + 1
	}
	if c == '"' || c == '`' {
		end := len(cs)
		for j := i + 1; j < len(cs); j++ {
			if cs[j] == c {
				end = j
				break
			}
		}
		body := cs[i+1 : end]
		ident := c == '"' && pg && end < len(cs) && len(body) >= 1 && len(body) <= 64
		for _, r := range body {
			if ident && !isAlnum(r) && r != '_' && r != '$' {
				ident = false
			}
		}
		if ident {
			out.WriteString(string(cs[i : end+1]))
		} else {
			out.WriteByte('?')
		}
		return end + 1
	}
	if c == '$' {
		if i+1 < len(cs) && isDigit(cs[i+1]) {
			i++
			for i < len(cs) && isDigit(cs[i]) {
				i++
			}
			out.WriteByte('?')
			return i
		}
		if end := dollarQuoted(cs, i); end >= 0 {
			out.WriteByte('?')
			return end
		}
	}
	switch {
	case isDigit(c):
		for i < len(cs) && (isWordRune(cs[i]) || cs[i] == '.') {
			i++
		}
		out.WriteByte('?')
	case isWordRune(c):
		for i < len(cs) && isWordRune(cs[i]) {
			out.WriteRune(cs[i])
			i++
		}
	default:
		out.WriteRune(c)
		i++
	}
	return i
}

// collapseIn follows the reference byte for byte, including its word-start check on the
// previous byte read as a Latin-1 character.
func collapseIn(s string) string {
	b := []byte(s)
	var out strings.Builder
	for i := 0; i < len(b); {
		atWord := i == 0 || !isWordRune(rune(b[i-1]))
		if atWord && len(b)-i >= 2 && strings.EqualFold(string(b[i:i+2]), "in") {
			if open, end, ok := inList(b, i+2); ok {
				out.Write(b[i:open])
				out.WriteString("(?+)")
				i = end
				continue
			}
		}
		r, n := utf8.DecodeRune(b[i:])
		out.WriteRune(r)
		i += n
	}
	return out.String()
}

func inList(b []byte, i int) (int, int, bool) {
	skip := func() {
		for i < len(b) && b[i] == ' ' {
			i++
		}
	}
	skip()
	open := i
	if i >= len(b) || b[i] != '(' {
		return 0, 0, false
	}
	i++
	for {
		skip()
		if i >= len(b) || b[i] != '?' {
			return 0, 0, false
		}
		i++
		skip()
		if i >= len(b) {
			return 0, 0, false
		}
		switch b[i] {
		case ',':
			i++
		case ')':
			return open, i + 1, true
		default:
			return 0, 0, false
		}
	}
}

// Hash is the canonical `db.query.hash` of normalized text (SQL from NormalizeSQL, or a
// document shape, Redis command pattern or Cypher text): XXH3-64, seed 0, as a decimal string.
func Hash(normalized string) string {
	return strconv.FormatUint(xxh3.HashString(normalized), 10)
}

// PGDialect reports the engines whose statements are normalized with the pg flag.
func PGDialect(system string) bool {
	switch system {
	case "postgresql", "cockroachdb", "redshift", "yugabytedb":
		return true
	}
	return false
}

// QueryHash is the canonical decimal db.query.hash of a raw statement.
func QueryHash(stmt string, pg bool) string {
	_, h := HashSQL(stmt, pg)
	return h
}
