package redact

import (
	"regexp"
	"strings"
)

// URLKeys are the span/log attribute keys that hold a request URL, target or path. The gateway
// scrubs them by default (ScrubURL); the API's redaction coverage checks the same list.
var URLKeys = []string{"http.target", "url.full", "url.path", "url.query", "http.url"}

// IsURLKey reports whether k is one of URLKeys.
func IsURLKey(k string) bool {
	for _, u := range URLKeys {
		if k == u {
			return true
		}
	}
	return false
}

// Placeholder replaces a path segment that looks like a secret.
const Placeholder = ":redacted"

// ScrubURL drops the query string and fragment of a URL, target or path, and replaces path
// segments that look like secrets with ":redacted": UUIDs, hex runs of 16+, JWTs, digit runs of
// 16+, and opaque tokens (16+ of [A-Za-z0-9_+=-] with a letter and a digit that are not a readable
// kebab/snake slug). Any userinfo is dropped too. The scheme and host are never touched.
// Idempotent. Same rule as the SDKs' urlScrubbing.
func ScrubURL(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	prefix := ""
	rest, ok := "", false
	if i := strings.Index(s, "://"); i >= 0 {
		prefix, rest, ok = s[:i+3], s[i+3:], true
	} else if strings.HasPrefix(s, "//") {
		prefix, rest, ok = "//", s[2:], true
	}
	if ok {
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		host := rest[:end]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		prefix, s = prefix+host, rest[end:]
	}
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		if secretSegment(seg) {
			segs[i] = Placeholder
		}
	}
	return prefix + strings.Join(segs, "/")
}

var (
	reUUID   = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHex    = regexp.MustCompile(`^(?i)[0-9a-f]{16,}$`)
	reJWT    = regexp.MustCompile(`^eyJ[\w-]*\.[\w-]+\.[\w-]*$`)
	reDigits = regexp.MustCompile(`^\d{16,}$`)
	reToken  = regexp.MustCompile(`^[A-Za-z0-9_+=-]{16,}$`)
	rePart   = regexp.MustCompile(`^([A-Za-z][a-z]*\d{0,2}|\d{1,4})$`)
	reDigit  = regexp.MustCompile(`\d`)
	reLetter = regexp.MustCompile(`[A-Za-z]`)
)

func secretSegment(seg string) bool {
	if reUUID.MatchString(seg) || reHex.MatchString(seg) || reJWT.MatchString(seg) || reDigits.MatchString(seg) {
		return true
	}
	if !reToken.MatchString(seg) || !reDigit.MatchString(seg) || !reLetter.MatchString(seg) {
		return false
	}
	for _, p := range strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' }) {
		if !rePart.MatchString(p) {
			return true
		}
	}
	return false // every part reads as a word: a slug
}
