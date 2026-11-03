package redact

import (
	"net/netip"
	"regexp"
	"strings"
)

// PIIPatterns is the gateway's selectable detector library (LOG-004), in match order: secrets
// first, then contact data, payment, national ids, network ids. The names and regexes are pinned
// with crates/wt-pipeline/src/stages/redact.rs KINDS by testdata/redaction/pii_kinds.json; the
// regexes stay inside the RE2 / Rust regex / ClickHouse common subset (no look-around). Kinds in
// piiChecks also need their checksum to hold.
var PIIPatterns = []Pattern{
	{Kind: "private_key", Regex: `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`},
	{Kind: "jwt", Regex: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`},
	{Kind: "aws_key", Regex: `(?:AKIA|ASIA)[0-9A-Z]{16}`},
	{Kind: "aws_secret", Regex: `(?i:aws_?secret_?access_?key)["']?\s*[:=]\s*["']?[A-Za-z0-9/+]{40}`},
	{Kind: "gcp_key", Regex: `AIza[0-9A-Za-z_-]{35}`},
	{Kind: "azure_storage_key", Regex: `AccountKey=[A-Za-z0-9+/]{86}==`},
	{Kind: "azure_sas", Regex: `\bsig=[A-Za-z0-9%+/=]{40,}`},
	{Kind: "azure_client_secret", Regex: `\b[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`},
	{Kind: "github_token", Regex: `gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82}`},
	{Kind: "gitlab_token", Regex: `glpat-[A-Za-z0-9_-]{20,}`},
	{Kind: "slack_token", Regex: `xox[bapers]-[A-Za-z0-9-]{10,}`},
	{Kind: "slack_webhook", Regex: `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`},
	{Kind: "stripe_key", Regex: `[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`},
	{Kind: "sendgrid_key", Regex: `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`},
	{Kind: "twilio_key", Regex: `\bSK[0-9a-fA-F]{32}\b`},
	{Kind: "npm_token", Regex: `\bnpm_[A-Za-z0-9]{36}\b`},
	{Kind: "email", Regex: `[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`},
	{Kind: "iban", Regex: `\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b`},
	{Kind: "card", Regex: `\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b`},
	{Kind: "uk_nino", Regex: `\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`},
	{Kind: "ca_sin", Regex: `\b\d{3}[ -]\d{3}[ -]\d{3}\b`},
	{Kind: "es_dni", Regex: `\b\d{8}-?[A-HJ-NP-TV-Z]\b`},
	{Kind: "fr_nir", Regex: `\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b`},
	{Kind: "br_cpf", Regex: `\b\d{3}\.?\d{3}\.?\d{3}-\d{2}\b`},
	{Kind: "in_aadhaar", Regex: `\b[2-9]\d{3} ?\d{4} ?\d{4}\b`},
	{Kind: "it_fiscal_code", Regex: `\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b`},
	{Kind: "passport", Regex: `(?i:(?:passport|reisepass|pasaporte|passeport|passaporto)(?:\s*(?:no\.?|number|nr\.?|num\.?|#))?)\s*[:#]?\s*[A-Z0-9]{6,9}\b`},
	{Kind: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`},
	{Kind: "phone", Regex: `\+\d{1,3}[ .-]?\(?\d{2,4}\)?[ .-]?\d{3,4}[ .-]?\d{3,4}\b`},
	{Kind: "mac", Regex: `\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b`},
	{Kind: "ipv4", Regex: `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
	{Kind: "ipv6", Regex: `\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b`},
}

// piiCompiled is PIIPatterns compiled once, with their checks (the patterns are constants).
var piiCompiled = func() []compiled {
	out := make([]compiled, len(PIIPatterns))
	for i, p := range PIIPatterns {
		out[i] = compiled{kind: p.Kind, re: regexp.MustCompile(p.Regex), check: piiChecks[p.Kind]}
	}
	return out
}()

// piiChecks are the checksums and range checks a match must pass (same rules in Rust).
var piiChecks = map[string]func(string) bool{
	"card":       Luhn,
	"ca_sin":     func(s string) bool { return luhnDigits(digitsOf(s)) },
	"es_dni":     validDNI,
	"fr_nir":     validNIR,
	"br_cpf":     validCPF,
	"in_aadhaar": func(s string) bool { return verhoeff(digitsOf(s)) },
	"ipv4":       validIPv4,
	"ipv6":       validIPv6,
}

func validIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

func validIPv6(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6()
}

// keywordWindow is how many bytes before a match a detector's keywords are looked for.
const keywordWindow = 64

func digitsOf(s string) []int {
	var d []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			d = append(d, int(c-'0'))
		}
	}
	return d
}

func luhnDigits(d []int) bool {
	sum := 0
	for i := range d {
		x := d[len(d)-1-i]
		if i%2 == 1 {
			if x *= 2; x > 9 {
				x -= 9
			}
		}
		sum += x
	}
	return len(d) > 0 && sum%10 == 0
}

// validDNI: the letter is "TRWAGMYFPDXBNJZSQVHLCKE"[number mod 23].
func validDNI(s string) bool {
	d := digitsOf(s)
	if len(d) != 8 {
		return false
	}
	n := 0
	for _, x := range d {
		n = n*10 + x
	}
	return s[len(s)-1] == "TRWAGMYFPDXBNJZSQVHLCKE"[n%23]
}

// validNIR: the two-digit key is 97 - (first 13 digits mod 97); Corsica (2A, 2B) shifts the number.
func validNIR(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != 15 {
		return false
	}
	body, shift := s[:13], 0
	if strings.Contains(body[5:7], "A") {
		body, shift = body[:5]+"19"+body[7:], 1_000_000
	} else if strings.Contains(body[5:7], "B") {
		body, shift = body[:5]+"18"+body[7:], 2_000_000
	}
	n, key := 0, 0
	for _, c := range body {
		n = n*10 + int(c-'0')
	}
	for _, c := range s[13:] {
		key = key*10 + int(c-'0')
	}
	return 97-(n-shift)%97 == key
}

// validCPF: two mod-11 check digits; a repeated digit (111.111.111-11) is not a CPF.
func validCPF(s string) bool {
	d := digitsOf(s)
	if len(d) != 11 || strings.Count(s, string(rune('0'+d[0]))) == 11 {
		return false
	}
	check := func(n int) int {
		sum := 0
		for i := range n {
			sum += d[i] * (n + 1 - i)
		}
		return sum * 10 % 11 % 10
	}
	return check(9) == d[9] && check(10) == d[10]
}

var (
	verD = [10][10]int{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}}
	verP = [8][10]int{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}}
)

// verhoeff is the Aadhaar check digit (dihedral group D5).
func verhoeff(d []int) bool {
	c := 0
	for i := range d {
		c = verD[c][verP[i%8][d[len(d)-1-i]]]
	}
	return len(d) == 12 && c == 0
}

// keeps reports whether a match at s[start:] counts: its checksum holds and, when the detector
// has keywords, one of them appears within keywordWindow bytes before it.
func (p compiled) keeps(s string, start int, m string) bool {
	if p.check != nil && !p.check(m) {
		return false
	}
	if len(p.keywords) == 0 {
		return true
	}
	win := strings.ToLower(s[max(0, start-keywordWindow):start])
	for _, k := range p.keywords {
		if strings.Contains(win, k) {
			return true
		}
	}
	return false
}
