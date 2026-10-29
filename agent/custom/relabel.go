package custom

import (
	"crypto/md5" //nolint:gosec // hashmod is defined on MD5 by Prometheus; not a security use
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// RelabelRule is one Prometheus `relabel_config` entry.
type RelabelRule struct {
	SourceLabels []string `json:"source_labels"`
	Separator    *string  `json:"separator"` // default ";"
	TargetLabel  string   `json:"target_label"`
	Regex        string   `json:"regex"` // default "(.*)"; anchored as ^(?:regex)$
	Modulus      uint64   `json:"modulus"`
	Replacement  *string  `json:"replacement"` // default "$1"
	Action       string   `json:"action"`      // default "replace"
}

var relabelActions = map[string]bool{
	"replace": true, "keep": true, "drop": true, "keepequal": true, "dropequal": true,
	"hashmod": true, "labelmap": true, "labeldrop": true, "labelkeep": true,
	"lowercase": true, "uppercase": true,
}

var reCache sync.Map // pattern -> *regexp.Regexp

func (r RelabelRule) re() (*regexp.Regexp, error) {
	pat := r.Regex
	if pat == "" {
		pat = "(.*)"
	}
	if v, ok := reCache.Load(pat); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile("^(?:" + pat + ")$")
	if err != nil {
		return nil, err
	}
	reCache.Store(pat, re)
	return re, nil
}

// ValidateRelabel checks the rules once so a bad config fails at load time, not on every scrape.
func ValidateRelabel(rules []RelabelRule) error {
	for i, r := range rules {
		act := r.act()
		if !relabelActions[act] {
			return fmt.Errorf("relabel rule %d: unknown action %q", i, r.Action)
		}
		if _, err := r.re(); err != nil {
			return fmt.Errorf("relabel rule %d: regex: %w", i, err)
		}
		switch act {
		case "replace", "hashmod", "lowercase", "uppercase", "keepequal", "dropequal":
			if r.TargetLabel == "" {
				return fmt.Errorf("relabel rule %d: %s needs target_label", i, act)
			}
		}
		if act == "hashmod" && r.Modulus == 0 {
			return fmt.Errorf("relabel rule %d: hashmod needs a modulus", i)
		}
	}
	return nil
}

func (r RelabelRule) act() string {
	if r.Action == "" {
		return "replace"
	}
	return strings.ToLower(r.Action)
}

// Relabel applies rules in order to a copy of labels. The bool is false when a keep or drop
// rule removed the target (the labels are then nil). A rule with an invalid regex or action is
// skipped; ValidateRelabel reports those at config load.
func Relabel(labels map[string]string, rules []RelabelRule) (map[string]string, bool) {
	cur := make(map[string]string, len(labels))
	for k, v := range labels {
		cur[k] = v
	}
	for _, r := range rules {
		re, err := r.re()
		if err != nil {
			continue
		}
		sep := ";"
		if r.Separator != nil {
			sep = *r.Separator
		}
		repl := "$1"
		if r.Replacement != nil {
			repl = *r.Replacement
		}
		vals := make([]string, len(r.SourceLabels))
		for i, n := range r.SourceLabels {
			vals[i] = cur[n]
		}
		val := strings.Join(vals, sep)
		switch r.act() {
		case "replace":
			m := re.FindStringSubmatchIndex(val)
			if m == nil {
				continue
			}
			target := string(re.ExpandString(nil, r.TargetLabel, val, m))
			if !validLabelName(target) {
				continue
			}
			if res := string(re.ExpandString(nil, repl, val, m)); res == "" {
				delete(cur, target)
			} else {
				cur[target] = res
			}
		case "lowercase":
			cur[r.TargetLabel] = strings.ToLower(val)
		case "uppercase":
			cur[r.TargetLabel] = strings.ToUpper(val)
		case "keep":
			if !re.MatchString(val) {
				return nil, false
			}
		case "drop":
			if re.MatchString(val) {
				return nil, false
			}
		case "keepequal":
			if val != cur[r.TargetLabel] {
				return nil, false
			}
		case "dropequal":
			if val == cur[r.TargetLabel] {
				return nil, false
			}
		case "hashmod":
			if r.Modulus > 0 {
				sum := md5.Sum([]byte(val)) //nolint:gosec
				cur[r.TargetLabel] = fmt.Sprint(binary.BigEndian.Uint64(sum[8:]) % r.Modulus)
			}
		case "labelmap":
			snap := make(map[string]string, len(cur))
			for k, v := range cur {
				snap[k] = v
			}
			for k, v := range snap { // iterate a copy so new names are not matched again
				if m := re.FindStringSubmatchIndex(k); m != nil {
					cur[string(re.ExpandString(nil, repl, k, m))] = v
				}
			}
		case "labeldrop":
			for k := range cur {
				if re.MatchString(k) {
					delete(cur, k)
				}
			}
		case "labelkeep":
			for k := range cur {
				if !re.MatchString(k) {
					delete(cur, k)
				}
			}
		}
	}
	return cur, true
}

func validLabelName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
