package trace

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode"
)

const maxStmt = 2048

// ParsePostgres extracts the statement of a simple Query ('Q') or extended Parse ('P') message.
func ParsePostgres(b []byte) (stmt string, ok bool) {
	if len(b) < 6 || (b[0] != 'Q' && b[0] != 'P') {
		return "", false
	}
	n := binary.BigEndian.Uint32(b[1:5])
	if n < 5 || n > 1<<24 {
		return "", false
	}
	body := b[5:]
	if b[0] == 'P' { // statement name, NUL, query
		_, rest, found := bytes.Cut(body, []byte{0})
		if !found {
			return "", false
		}
		body = rest
	}
	q, _, _ := bytes.Cut(body, []byte{0}) // truncated captures end without the NUL
	return string(q), len(q) > 0
}

// IsPostgresResponse recognises the first backend message of a reply and whether it is an error.
func IsPostgresResponse(b []byte) (ok, isErr bool) {
	if len(b) < 5 || !bytes.Contains([]byte("TCDEZ1"), b[:1]) {
		return false, false
	}
	n := binary.BigEndian.Uint32(b[1:5])
	return n >= 4 && n < 1<<24, b[0] == 'E'
}

// ParseMySQL extracts the statement of a COM_QUERY or COM_STMT_PREPARE packet.
func ParseMySQL(b []byte) (stmt string, ok bool) {
	if len(b) < 6 || b[3] != 0 { // sequence 0 starts a command
		return "", false
	}
	if b[4] != 0x03 && b[4] != 0x16 {
		return "", false
	}
	return string(b[5:]), true
}

// IsMySQLResponse recognises a reply packet (sequence >= 1) and whether it is ERR.
func IsMySQLResponse(b []byte) (ok, isErr bool) {
	if len(b) < 5 || b[3] == 0 {
		return false, false
	}
	return true, b[4] == 0xff
}

// ParseRedis returns only the command name of a RESP array. Arguments (keys, values) are never
// read, so nothing but the verb leaves the host.
func ParseRedis(b []byte) (cmd string, ok bool) {
	if len(b) < 8 || b[0] != '*' {
		return "", false
	}
	_, rest, found := bytes.Cut(b, []byte("\r\n"))
	if !found || len(rest) < 4 || rest[0] != '$' {
		return "", false
	}
	_, rest, found = bytes.Cut(rest, []byte("\r\n"))
	if !found {
		return "", false
	}
	c, _, _ := bytes.Cut(rest, []byte("\r\n"))
	if len(c) == 0 || len(c) > 32 {
		return "", false
	}
	for _, r := range string(c) {
		if !unicode.IsLetter(r) {
			return "", false
		}
	}
	return strings.ToUpper(string(c)), true
}

// IsRedisResponse recognises a RESP reply and whether it is an error.
func IsRedisResponse(b []byte) (ok, isErr bool) {
	if len(b) == 0 {
		return false, false
	}
	switch b[0] {
	case '+', ':', '$', '*', '_':
		return true, false
	case '-':
		return true, true
	}
	return false, false
}

// NormalizeSQL mirrors the worker's normalize_sql (services/worker/src/sqlnorm.rs): literals
// become ?, comments go, whitespace collapses, IN lists collapse to IN (?+). It over-masks
// (an unterminated string or comment masks to the end) and never keeps a literal.
func NormalizeSQL(stmt string, pg bool) string {
	cs := []rune(stmt)
	if len(cs) > maxStmt {
		cs = cs[:maxStmt]
	}
	at := func(i int) rune {
		if i < len(cs) {
			return cs[i]
		}
		return 0
	}
	var out strings.Builder
	space := false
	for i := 0; i < len(cs); {
		c := cs[i]
		switch {
		case unicode.IsSpace(c):
			space = true
			i++
		case c == '/' && at(i+1) == '*':
			depth := 1
			for i += 2; i < len(cs) && depth > 0; {
				switch {
				case cs[i] == '/' && at(i+1) == '*':
					depth, i = depth+1, i+2
				case cs[i] == '*' && at(i+1) == '/':
					depth, i = depth-1, i+2
				default:
					i++
				}
			}
			space = true
		case (c == '-' && at(i+1) == '-') || (c == '#' && !pg):
			for i < len(cs) && cs[i] != '\n' {
				i++
			}
			space = true
		default:
			if space && out.Len() > 0 {
				out.WriteByte(' ')
			}
			space = false
			i = token(cs, i, pg, &out)
		}
	}
	return collapseIn(out.String())
}

func isIdent(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

func token(cs []rune, i int, pg bool, out *strings.Builder) int {
	c := cs[i]
	switch {
	case c == '\'' || (!pg && (c == '"' || c == '`')):
		j := i + 1
		for j < len(cs) {
			if cs[j] == c {
				if j+1 < len(cs) && cs[j+1] == c {
					j += 2
					continue
				}
				break
			}
			if cs[j] == '\\' && !pg {
				j++
			}
			j++
		}
		out.WriteByte('?')
		return min(j+1, len(cs))
	case c == '$' && i+1 < len(cs) && unicode.IsDigit(cs[i+1]):
		j := i + 1
		for j < len(cs) && unicode.IsDigit(cs[j]) {
			j++
		}
		out.WriteByte('?')
		return j
	case c == '$': // dollar-quoted string $tag$...$tag$
		j := i + 1
		for j < len(cs) && isIdent(cs[j]) {
			j++
		}
		if j < len(cs) && cs[j] == '$' {
			tag := string(cs[i : j+1])
			out.WriteByte('?')
			if end := strings.Index(string(cs[j+1:]), tag); end >= 0 {
				return j + 1 + len([]rune(string(cs[j+1:])[:end+len(tag)]))
			}
			return len(cs)
		}
		out.WriteRune(c)
		return i + 1
	case unicode.IsDigit(c):
		j := i
		for j < len(cs) && (isIdent(cs[j]) || cs[j] == '.') {
			j++
		}
		out.WriteByte('?')
		return j
	case unicode.IsLetter(c) || c == '_':
		j := i
		for j < len(cs) && (isIdent(cs[j]) || cs[j] == '$') {
			j++
		}
		out.WriteString(string(cs[i:j]))
		return j
	}
	out.WriteRune(c)
	return i + 1
}

// collapseIn turns "IN (?, ?, ?)" into "IN (?+)".
func collapseIn(s string) string {
	const pat = " IN (?"
	i := strings.Index(strings.ToUpper(s), pat)
	if i < 0 {
		return s
	}
	j := i + len(" IN (")
	k := j
	for k < len(s) && (s[k] == '?' || s[k] == ',' || s[k] == ' ') {
		k++
	}
	if k < len(s) && s[k] == ')' && strings.Count(s[j:k], "?") >= 2 {
		return s[:j] + "?+" + collapseIn(s[k:])
	}
	return s[:j] + collapseIn(s[j:])
}
