// Package sink is the write side every collector module uses. The agent's OTLP exporter
// satisfies it; tests use a recorder.
package sink

import (
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Sink receives samples and log records.
type Sink interface {
	Gauge(name, unit string, value float64, attrs map[string]string, at time.Time)
	// Sum is a cumulative monotonic counter.
	Sum(name, unit string, value float64, attrs map[string]string, at time.Time)
	Log(severity, body string, attrs map[string]string, at time.Time)
}

// Sample is one recorded point or log record.
type Sample struct {
	Name  string
	Value float64
	Attrs map[string]string
	Body  string
	Sev   string
}

// Recorder is a Sink that keeps everything it is given (for tests).
type Recorder struct {
	mu      sync.Mutex
	Samples []Sample
}

// Gauge records a gauge point.
func (r *Recorder) Gauge(name, _ string, v float64, a map[string]string, _ time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Samples = append(r.Samples, Sample{Name: name, Value: v, Attrs: a})
}

// Sum records a counter point.
func (r *Recorder) Sum(name, unit string, v float64, a map[string]string, at time.Time) {
	r.Gauge(name, unit, v, a, at)
}

// Log records a log record.
func (r *Recorder) Log(sev, body string, a map[string]string, _ time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Samples = append(r.Samples, Sample{Sev: sev, Body: body, Attrs: a})
}

// Snapshot returns a copy of what was recorded so far (safe while collectors still write).
func (r *Recorder) Snapshot() []Sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Sample(nil), r.Samples...)
}

// Names returns the distinct metric names recorded.
func (r *Recorder) Names() map[string]bool {
	m := map[string]bool{}
	for _, s := range r.Samples {
		if s.Name != "" {
			m[s.Name] = true
		}
	}
	return m
}

// With copies attrs and adds the key/value pairs in kv on top; it never mutates attrs.
func With(attrs map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(attrs)+len(kv)/2)
	for k, v := range attrs {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// Truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ResourcePrefix marks, inside the modules that Hoist, an attribute that belongs on the
// OTLP resource. The exporter itself never reads it: Hoist (applied only by trusted modules: Kubernetes, virtualization, cloud and docker, whose values come from an API and not from scraped input)
// turns the prefixed keys into explicit resource arguments, so a scraped label or any other
// module's attribute can never name the resource. Keys must not be `wt.*` (ingest deletes them).
const ResourcePrefix = "resource."

// ResourceSink is a Sink that also accepts resource attributes as a separate argument.
type ResourceSink interface {
	GaugeRes(name, unit string, value float64, res, attrs map[string]string, at time.Time)
	SumRes(name, unit string, value float64, res, attrs map[string]string, at time.Time)
	LogRes(severity, body string, res, attrs map[string]string, at time.Time)
}

// SplitRes separates ResourcePrefix keys (prefix removed) from the rest. With none it returns
// (nil, attrs) unchanged.
func SplitRes(attrs map[string]string) (res, rest map[string]string) {
	has := false
	for k := range attrs {
		if strings.HasPrefix(k, ResourcePrefix) {
			has = true
			break
		}
	}
	if !has {
		return nil, attrs
	}
	res, rest = map[string]string{}, map[string]string{}
	for k, v := range attrs {
		if r, ok := strings.CutPrefix(k, ResourcePrefix); ok {
			res[r] = v
		} else {
			rest[k] = v
		}
	}
	return res, rest
}

// Strip returns attrs without ResourcePrefix keys (a copy only when one is present). Modules
// that copy outside input into attributes use it.
func Strip(attrs map[string]string) map[string]string {
	_, rest := SplitRes(attrs)
	return rest
}

type hoister struct{ rs ResourceSink }

// Hoist wraps out so ResourcePrefix keys become resource attributes. It is used only by the
// Kubernetes modules; out is returned unchanged when it cannot take resource attributes (then
// the prefixed keys stay ordinary attributes).
func Hoist(out Sink) Sink {
	if rs, ok := out.(ResourceSink); ok {
		return hoister{rs}
	}
	return out
}

func (h hoister) Gauge(n, u string, v float64, a map[string]string, at time.Time) {
	res, rest := SplitRes(a)
	h.rs.GaugeRes(n, u, v, res, rest, at)
}

func (h hoister) Sum(n, u string, v float64, a map[string]string, at time.Time) {
	res, rest := SplitRes(a)
	h.rs.SumRes(n, u, v, res, rest, at)
}

func (h hoister) Log(sev, body string, a map[string]string, at time.Time) {
	res, rest := SplitRes(a)
	h.rs.LogRes(sev, body, res, rest, at)
}

// Res returns attrs with every key addressed to the resource.
func Res(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[ResourcePrefix+k] = v
	}
	return out
}
