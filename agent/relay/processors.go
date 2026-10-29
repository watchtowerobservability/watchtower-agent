package relay

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"regexp"
	"strconv"
	"strings"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// The edge-safe processors: exactly the Rust stages `redact`, `filter`, `sample` and `enrich`
// (crates/wt-pipeline) with the same config schema. Both implementations run
// testdata/pipeline_vectors.json. The one deliberate difference: the relay never emits wt.*
// attributes (the Rust sample stage stamps wt.sample_rate; the gateway owns that namespace),
// and it deletes every wt.* attribute it sees.

const (
	redacted    = "[REDACTED]"
	maxAttrs    = 256 // wt_telemetry::limits::MAX_ATTRS
	maxPatterns = 50  // wt_pipeline::MAX_PATTERNS
)

// ProcessorConfig is `pipeline_versions.config` restricted to the edge-safe stages.
type ProcessorConfig struct {
	Version int     `json:"version" yaml:"version"`
	Stages  []Stage `json:"stages" yaml:"stages"`
}

// Stage is one processor; fields mirror the Rust StageConfig variants.
type Stage struct {
	Type     string   `json:"type" yaml:"type"`
	Keys     []string `json:"keys,omitempty" yaml:"keys"`
	Patterns []string `json:"patterns,omitempty" yaml:"patterns"`
	DropIf   *DropIf  `json:"drop_if,omitempty" yaml:"drop_if"`
	Rate     float64  `json:"rate,omitempty" yaml:"rate"`
	By       string   `json:"by,omitempty" yaml:"by"`
	// KeepMinSeverity: log records at or above this OTel severity number always survive `sample`.
	KeepMinSeverity *uint8            `json:"keep_min_severity,omitempty" yaml:"keep_min_severity"`
	Set             map[string]string `json:"set,omitempty" yaml:"set"`
}

// DropIf drops a record whose attribute (else resource attribute) equals Eq.
type DropIf struct {
	Attr string `json:"attr" yaml:"attr"`
	Eq   string `json:"eq" yaml:"eq"`
}

// rec is what a stage sees of one log record or span.
type rec struct {
	attrs, res *[]*commonpb.KeyValue
	extra      []*[]*commonpb.KeyValue // span event and link attributes
	texts      []*string               // body, span name, status message, event names
	trace      []byte                  // nil when the record has no usable trace id
	severity   int32                   // logs only; 0 otherwise
	dead       bool
}

func (r *rec) maps() []*[]*commonpb.KeyValue {
	m := []*[]*commonpb.KeyValue{r.attrs}
	if r.res != nil {
		m = append(m, r.res)
	}
	return append(m, r.extra...)
}

type stage interface{ apply(recs []*rec) }

// Processors is a compiled stage list.
type Processors struct {
	stages []stage
	def    *redactor
}

var defaultRedactor = mustRedactor(
	`(?i)^(?:http\.(?:request|response)\.header\.)?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|password|passwd|secret|token|access[-_]token|refresh[-_]token|client[-_]secret)$`,
	`(?i:bearer\s+[A-Za-z0-9._~+/-]+=*)|AKIA[0-9A-Z]{16}|wt[ik]_[a-z0-9]{8}_[A-Za-z0-9_-]{43}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
)

// Compile validates cfg like the Rust compiler does (unknown stage types, bad rates and
// patterns, enrich of wt.* are errors).
func Compile(cfg ProcessorConfig) (*Processors, error) {
	if cfg.Version != 1 && len(cfg.Stages) > 0 {
		return nil, fmt.Errorf("unsupported processors version %d", cfg.Version)
	}
	n := 0
	for _, s := range cfg.Stages {
		n += len(s.Patterns)
	}
	if n > maxPatterns {
		return nil, fmt.Errorf("%d redact patterns, at most %d", n, maxPatterns)
	}
	p := &Processors{def: defaultRedactor}
	for i, s := range cfg.Stages {
		st, err := compileStage(s)
		if err != nil {
			return nil, fmt.Errorf("stage %d (%s): %w", i, s.Type, err)
		}
		p.stages = append(p.stages, st)
	}
	return p, nil
}

func compileStage(s Stage) (stage, error) {
	switch s.Type {
	case "redact":
		return newRedactor("", s.Keys, s.Patterns...)
	case "filter":
		if s.DropIf == nil {
			return nil, errors.New("drop_if is required")
		}
		return filterStage{*s.DropIf}, nil
	case "sample":
		if s.By == "" || len(s.By) > 128 {
			return nil, errors.New("sample `by` must be trace_id or an attribute key")
		}
		if !(s.Rate >= 0 && s.Rate <= 1) {
			return nil, errors.New("sample rate must be within 0..=1")
		}
		const maxU = math.MaxUint64
		var f float64 = maxU
		st := sampleStage{rate: s.Rate, threshold: uint64(s.Rate * f), minSev: -1}
		if s.By != "trace_id" {
			st.by = s.By
		}
		if s.KeepMinSeverity != nil {
			st.minSev = int32(*s.KeepMinSeverity)
		}
		return st, nil
	case "enrich":
		for k := range s.Set {
			if strings.HasPrefix(k, "wt.") {
				return nil, errors.New("enrich cannot set wt.* attributes")
			}
		}
		return enrichStage{s.Set}, nil
	}
	return nil, fmt.Errorf("%q is not an edge-safe processor (redact, filter, sample, enrich)", s.Type)
}

// Logs applies the processors in place and returns how many records are left.
func (p *Processors) Logs(req *collogs.ExportLogsServiceRequest) int {
	var recs []*rec
	for _, rl := range req.GetResourceLogs() {
		if rl.Resource == nil {
			rl.Resource = &resourcepb.Resource{}
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				r := &rec{attrs: &lr.Attributes, res: &rl.Resource.Attributes, trace: usableTrace(lr.TraceId), severity: int32(lr.SeverityNumber)}
				if sv, ok := lr.GetBody().GetValue().(*commonpb.AnyValue_StringValue); ok {
					r.texts = []*string{&sv.StringValue}
				}
				recs = append(recs, r)
			}
		}
	}
	p.run(recs)
	i := 0
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			out := sl.LogRecords[:0]
			for _, lr := range sl.LogRecords {
				if !recs[i].dead {
					out = append(out, lr)
				}
				i++
			}
			sl.LogRecords = out
		}
	}
	return countLogs(req)
}

func countLogs(req *collogs.ExportLogsServiceRequest) int {
	n := 0
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			n += len(sl.GetLogRecords())
		}
	}
	return n
}

// Traces applies the processors in place and returns how many spans are left.
func (p *Processors) Traces(req *coltrace.ExportTraceServiceRequest) int {
	var recs []*rec
	for _, rs := range req.GetResourceSpans() {
		if rs.Resource == nil {
			rs.Resource = &resourcepb.Resource{}
		}
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				r := &rec{attrs: &sp.Attributes, res: &rs.Resource.Attributes, trace: usableTrace(sp.TraceId)}
				r.texts = append(r.texts, &sp.Name)
				if sp.Status != nil {
					r.texts = append(r.texts, &sp.Status.Message)
				}
				for _, e := range sp.Events {
					r.texts = append(r.texts, &e.Name)
					r.extra = append(r.extra, &e.Attributes)
				}
				for _, l := range sp.Links {
					r.extra = append(r.extra, &l.Attributes)
				}
				recs = append(recs, r)
			}
		}
	}
	p.run(recs)
	i := 0
	n := 0
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			out := ss.Spans[:0]
			for _, sp := range ss.Spans {
				if !recs[i].dead {
					out = append(out, sp)
					n++
				}
				i++
			}
			ss.Spans = out
		}
	}
	return n
}

func usableTrace(t []byte) []byte {
	if len(t) != 16 || bytes.Equal(t, make([]byte, 16)) {
		return nil
	}
	return t
}

func (p *Processors) run(recs []*rec) {
	p.def.apply(recs)
	for _, s := range p.stages {
		s.apply(recs)
	}
	p.def.apply(recs)
	for _, r := range recs {
		for _, m := range r.maps() {
			delWT(m)
		}
	}
}

// --- attribute helpers --------------------------------------------------------------------

func delWT(m *[]*commonpb.KeyValue) {
	out := (*m)[:0]
	for _, kv := range *m {
		if !strings.HasPrefix(kv.Key, "wt.") {
			out = append(out, kv)
		}
	}
	*m = out
}

// strOf is the string form of a scalar value; arrays, maps and bytes have none.
func strOf(v *commonpb.AnyValue) (string, bool) {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue, true
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10), true
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue), true
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'f', -1, 64), true
	}
	return "", false
}

func lookup(m []*commonpb.KeyValue, key string) (string, bool) {
	for _, kv := range m {
		if kv.Key == key {
			return strOf(kv.Value)
		}
	}
	return "", false
}

func strVal(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

// setStr overwrites or appends; a new key past maxAttrs is skipped like the Rust stage.
func setStr(m *[]*commonpb.KeyValue, k, v string) {
	for _, kv := range *m {
		if kv.Key == k {
			kv.Value = strVal(v)
			return
		}
	}
	if len(*m) < maxAttrs {
		*m = append(*m, &commonpb.KeyValue{Key: k, Value: strVal(v)})
	}
}

// --- redact -------------------------------------------------------------------------------

type redactor struct {
	keyRe *regexp.Regexp
	keys  map[string]bool
	pats  []*regexp.Regexp
}

func mustRedactor(keyRe string, pats ...string) *redactor {
	r, err := newRedactor(keyRe, nil, pats...)
	if err != nil {
		panic(err)
	}
	return r
}

func newRedactor(keyRe string, keys []string, pats ...string) (*redactor, error) {
	r := &redactor{keys: map[string]bool{}}
	if keyRe != "" {
		re, err := regexp.Compile(keyRe)
		if err != nil {
			return nil, err
		}
		r.keyRe = re
	}
	for _, k := range keys {
		r.keys[strings.ToLower(k)] = true
	}
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", p, err)
		}
		r.pats = append(r.pats, re)
	}
	return r, nil
}

func (r *redactor) secretKey(k string) bool {
	return (r.keyRe != nil && r.keyRe.MatchString(k)) || r.keys[strings.ToLower(k)]
}

func (r *redactor) mask(s string) string {
	for _, re := range r.pats {
		s = re.ReplaceAllLiteralString(s, redacted)
	}
	return s
}

func (r *redactor) apply(recs []*rec) {
	for _, rc := range recs {
		if rc.dead {
			continue
		}
		for _, t := range rc.texts {
			*t = r.mask(*t)
		}
		for _, m := range rc.maps() {
			for _, kv := range *m {
				if r.secretKey(kv.Key) {
					kv.Value = strVal(redacted)
				} else if sv, ok := kv.Value.GetValue().(*commonpb.AnyValue_StringValue); ok {
					sv.StringValue = r.mask(sv.StringValue)
				}
			}
		}
	}
}

// --- filter, sample, enrich ---------------------------------------------------------------

type filterStage struct{ d DropIf }

func (f filterStage) apply(recs []*rec) {
	for _, r := range recs {
		v, ok := lookup(*r.attrs, f.d.Attr)
		if !ok && r.res != nil {
			v, ok = lookup(*r.res, f.d.Attr)
		}
		if ok && v == f.d.Eq {
			r.dead = true
		}
	}
}

type sampleStage struct {
	rate      float64
	threshold uint64
	by        string // "" = trace id, else the attribute (or resource attribute) hashed with FNV-1a 64
	minSev    int32  // -1 = no severity floor
}

// apply keeps a record when the low 8 bytes (big endian) of its trace id (or the FNV-1a hash of
// its `by` attribute) are below the threshold, so every signal of one trace agrees; records
// without a key are kept, as are those at or above the severity floor.
func (s sampleStage) apply(recs []*rec) {
	if s.rate >= 1 {
		return
	}
	for _, r := range recs {
		if s.minSev >= 0 && r.severity >= s.minSev {
			continue
		}
		var v uint64
		if s.by != "" {
			val, ok := lookup(*r.attrs, s.by)
			if !ok && r.res != nil {
				val, ok = lookup(*r.res, s.by)
			}
			if !ok {
				continue
			}
			h := fnv.New64a()
			_, _ = h.Write([]byte(val))
			v = h.Sum64()
		} else {
			if r.trace == nil {
				continue
			}
			for _, b := range r.trace[8:16] {
				v = v<<8 | uint64(b)
			}
		}
		if v >= s.threshold {
			r.dead = true
		}
	}
}

type enrichStage struct{ set map[string]string }

func (e enrichStage) apply(recs []*rec) {
	for _, r := range recs {
		if r.dead {
			continue
		}
		for k, v := range e.set {
			setStr(r.attrs, k, v)
		}
	}
}
