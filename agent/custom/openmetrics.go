package custom

import (
	"sort"
	"strconv"
	"strings"
)

// The OpenMetrics text format differs from the Prometheus one in a few places that matter here:
// `# EOF`, `# UNIT`, counter families declared without `_total`, `_created` series, timestamps
// in seconds, and exemplars after the sample (`... 1 # {trace_id="a"} 0.5 1700000000.1`). The
// expfmt text parser knows none of that, so omToText rewrites the body into the Prometheus
// text format and returns the exemplars it cut out, keyed by exemplarKey.

type exemplar struct {
	labels map[string]string
	value  string
}

// exemplarKey identifies a series: the sample name, its labels without `le`, and `le`.
func exemplarKey(name string, labels map[string]string, le string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	for _, k := range keys {
		b.WriteString("\x00" + k + "=" + labels[k])
	}
	b.WriteString("\x00le=" + le)
	return b.String()
}

func normLe(s string) string {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return s
}

func omToText(body string) (string, map[string]exemplar) {
	lines := strings.Split(body, "\n")
	counters := map[string]bool{}
	for _, ln := range lines {
		if f := strings.Fields(ln); len(f) == 4 && f[0] == "#" && f[1] == "TYPE" && f[3] == "counter" {
			counters[f[2]] = true
		}
	}
	exs := map[string]exemplar{}
	var out strings.Builder
	for _, ln := range lines {
		switch {
		case ln == "" || ln == "# EOF" || strings.HasPrefix(ln, "# UNIT "):
		case strings.HasPrefix(ln, "# TYPE ") || strings.HasPrefix(ln, "# HELP "):
			f := strings.SplitN(ln, " ", 4)
			if len(f) >= 3 && counters[f[2]] {
				f[2] += "_total"
			}
			if len(f) == 4 && f[1] == "TYPE" {
				switch f[3] {
				case "unknown", "info", "stateset", "gaugehistogram":
					f[3] = "untyped"
				}
			}
			out.WriteString(strings.Join(f, " ") + "\n")
		case strings.HasPrefix(ln, "#"):
		default:
			if s, ok := omSample(ln, exs); ok {
				out.WriteString(s + "\n")
			}
		}
	}
	return out.String(), exs
}

// omSample converts one sample line; false drops it (`_created`).
func omSample(ln string, exs map[string]exemplar) (string, bool) {
	name, lblText, labels, rest, ok := splitSample(ln)
	if !ok {
		return ln, true // let the text parser judge it
	}
	if strings.HasSuffix(name, "_created") {
		return "", false
	}
	sample, ex, hasEx := strings.Cut(rest, " # ")
	fields := strings.Fields(sample)
	if len(fields) == 0 {
		return ln, true
	}
	if len(fields) > 1 {
		if sec, err := strconv.ParseFloat(fields[1], 64); err == nil {
			fields[1] = strconv.FormatInt(int64(sec*1000), 10)
		}
	}
	if hasEx {
		if _, _, exl, exrest, ok := splitSample("x" + strings.TrimSpace(ex)); ok && len(exl) > 0 {
			if v := strings.Fields(exrest); len(v) > 0 {
				le := ""
				if strings.HasSuffix(name, "_bucket") {
					le = normLe(labels["le"])
					delete(labels, "le")
				}
				exs[exemplarKey(name, labels, le)] = exemplar{labels: exl, value: v[0]}
			}
		}
	}
	return name + lblText + " " + strings.Join(fields, " "), true
}

// splitSample splits `name{k="v",...} rest`. lblText is the `{...}` part verbatim (or empty).
func splitSample(ln string) (name, lblText string, labels map[string]string, rest string, ok bool) {
	i := strings.IndexAny(ln, "{ ")
	if i < 0 {
		return "", "", nil, "", false
	}
	name, labels = ln[:i], map[string]string{}
	if ln[i] == ' ' {
		return name, "", labels, strings.TrimSpace(ln[i:]), true
	}
	j, inQ := i+1, false
	for ; j < len(ln); j++ {
		c := ln[j]
		if inQ && c == '\\' {
			j++
		} else if c == '"' {
			inQ = !inQ
		} else if c == '}' && !inQ {
			break
		}
	}
	if j >= len(ln) {
		return "", "", nil, "", false
	}
	lblText, rest = ln[i:j+1], strings.TrimSpace(ln[j+1:])
	body := ln[i+1 : j]
	for body != "" {
		k, v, found := strings.Cut(body, "=\"")
		if !found {
			break
		}
		var val strings.Builder
		n := 0
		for ; n < len(v); n++ {
			if v[n] == '\\' && n+1 < len(v) {
				n++
				switch v[n] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(v[n])
				}
			} else if v[n] == '"' {
				break
			} else {
				val.WriteByte(v[n])
			}
		}
		labels[strings.TrimSpace(strings.TrimPrefix(k, ","))] = val.String()
		if n+1 >= len(v) {
			break
		}
		body = strings.TrimPrefix(v[n+1:], ",")
	}
	return name, lblText, labels, rest, true
}
