package custom

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const dogMaxPending = 1000 // events and checks held between flushes

// DogMapping is one name-mapping rule (statsd_exporter style).
type DogMapping struct {
	Match  string            `json:"match"`  // dotted glob, `*` = exactly one segment
	Name   string            `json:"name"`   // new metric name, $1.. = captures
	Labels map[string]string `json:"labels"` // extra tags, values may use $1..
}

type dogMap struct {
	segs []string
	DogMapping
}

var dogRef = regexp.MustCompile(`\$(\d+)`)

func compileDogMaps(in []DogMapping) []dogMap {
	out := make([]dogMap, 0, len(in))
	for _, m := range in {
		if m.Match != "" && m.Name != "" {
			out = append(out, dogMap{strings.Split(m.Match, "."), m})
		}
	}
	return out
}

func expandRefs(s string, caps []string) string {
	return dogRef.ReplaceAllStringFunc(s, func(r string) string {
		if i, err := strconv.Atoi(r[1:]); err == nil && i >= 1 && i <= len(caps) {
			return caps[i-1]
		}
		return ""
	})
}

// remap returns the mapped name and adds the rule's labels to tags; no rule matching leaves both.
func (d *DogStatsD) remap(name string, tags map[string]string) string {
	parts := strings.Split(name, ".")
next:
	for _, m := range d.maps {
		if len(m.segs) != len(parts) {
			continue
		}
		var caps []string
		for i, sg := range m.segs {
			switch {
			case sg == "*":
				caps = append(caps, parts[i])
			case sg != parts[i]:
				continue next
			}
		}
		for k, v := range m.Labels {
			tags[k] = expandRefs(v, caps)
		}
		return expandRefs(m.Name, caps)
	}
	return name
}

func parseDogTags(field string, tags map[string]string) {
	for _, t := range strings.Split(field[1:], ",") {
		if k, v, has := strings.Cut(t, ":"); k != "" {
			if !has {
				v = "true"
			}
			tags[k] = v
		}
	}
}

type dogEvent struct {
	title, text, host, alert, prio, agg, src string
	at                                       time.Time
	tags                                     map[string]string
}

type dogCheck struct {
	name, host, msg string
	status          float64
	at              time.Time
	tags            map[string]string
}

// special parses an `_e{..}` event or `_sc|` service check line (d.mu held) and buffers it.
func (d *DogStatsD) special(ln string) bool {
	if len(d.events)+len(d.checks) >= dogMaxPending {
		d.dropped++
		return true
	}
	if strings.HasPrefix(ln, "_sc|") {
		return d.serviceCheck(strings.Split(ln[4:], "|"))
	}
	hdr, rest, ok := strings.Cut(ln[3:], "}:")
	tl, xl, ok2 := strings.Cut(hdr, ",")
	tn, e1 := strconv.Atoi(tl)
	xn, e2 := strconv.Atoi(xl)
	if !ok || !ok2 || e1 != nil || e2 != nil || tn < 0 || xn < 0 || len(rest) < tn+1+xn || rest[tn] != '|' {
		return false
	}
	ev := dogEvent{title: rest[:tn], text: strings.ReplaceAll(rest[tn+1:tn+1+xn], `\n`, "\n"), at: time.Now(), tags: map[string]string{}}
	tail := rest[tn+1+xn:]
	if tail != "" && tail[0] != '|' {
		return false
	}
	for _, f := range strings.Split(tail, "|") {
		switch {
		case strings.HasPrefix(f, "d:"):
			if ts, err := strconv.ParseInt(f[2:], 10, 64); err == nil && ts > 0 {
				ev.at = time.Unix(ts, 0)
			}
		case strings.HasPrefix(f, "h:"):
			ev.host = f[2:]
		case strings.HasPrefix(f, "p:"):
			ev.prio = f[2:]
		case strings.HasPrefix(f, "t:"):
			ev.alert = f[2:]
		case strings.HasPrefix(f, "k:"):
			ev.agg = f[2:]
		case strings.HasPrefix(f, "s:"):
			ev.src = f[2:]
		case strings.HasPrefix(f, "#"):
			parseDogTags(f, ev.tags)
		}
	}
	d.events = append(d.events, ev)
	return true
}

func (d *DogStatsD) serviceCheck(f []string) bool {
	if len(f) < 2 || f[0] == "" {
		return false
	}
	st, err := strconv.Atoi(f[1])
	if err != nil || st < 0 || st > 3 {
		return false
	}
	c := dogCheck{name: f[0], status: float64(st), at: time.Now(), tags: map[string]string{}}
	for i, x := range f[2:] {
		switch {
		case strings.HasPrefix(x, "d:"):
			if ts, err := strconv.ParseInt(x[2:], 10, 64); err == nil && ts > 0 {
				c.at = time.Unix(ts, 0)
			}
		case strings.HasPrefix(x, "h:"):
			c.host = x[2:]
		case strings.HasPrefix(x, "#"):
			parseDogTags(x, c.tags)
		case strings.HasPrefix(x, "m:"):
			c.msg = strings.Join(append([]string{x[2:]}, f[2+i+1:]...), "|") // the message is last and may hold '|'
			d.checks = append(d.checks, c)
			return true
		}
	}
	d.checks = append(d.checks, c)
	return true
}

// flushSpecial writes the buffered events and service checks (d.mu held).
func (d *DogStatsD) flushSpecial(out Sink) {
	for _, c := range d.checks {
		a := sink.With(sink.Strip(c.tags), "check", c.name)
		if c.host != "" {
			a["host.name"] = c.host
		}
		if c.msg != "" {
			a["message"] = c.msg
		}
		out.Gauge("datadog.check_run.status", "", c.status, a, c.at)
	}
	ls, _ := out.(logSink)
	for _, e := range d.events {
		if ls == nil {
			d.ignored++ // this exporter takes no log records
			continue
		}
		a := sink.With(sink.Strip(e.tags), "datadog.event", "true")
		for k, v := range map[string]string{
			"host.name": e.host, "datadog.event.alert_type": e.alert, "datadog.event.priority": e.prio,
			"datadog.event.aggregation_key": e.agg, "datadog.event.source_type_name": e.src,
		} {
			if v != "" {
				a[k] = v
			}
		}
		body := e.title
		if e.text != "" {
			body += "\n" + e.text
		}
		sev := map[string]string{"error": "error", "warning": "warn"}[e.alert]
		if sev == "" {
			sev = "info"
		}
		ls.Log(sev, body, a, e.at)
	}
	d.events, d.checks = nil, nil
}
