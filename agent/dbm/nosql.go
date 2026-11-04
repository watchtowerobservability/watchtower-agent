package dbm

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// maxSample bounds one sample record's body.
const maxSample = 8 << 10

// Shape replaces every scalar of a decoded JSON document with "?", keeps keys and operators and
// collapses each array to its first element's shape, so a document query (MongoDB filter,
// Elasticsearch DSL, Cypher params) reads as its shape and never carries a value.
func Shape(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = Shape(x)
		}
		return m
	case []any:
		if len(t) == 0 {
			return []any{}
		}
		return []any{Shape(t[0])}
	case nil:
		return nil
	}
	return "?"
}

// ShapeText is Shape as compact JSON with sorted keys (encoding/json sorts map keys), so equal
// shapes give equal text and therefore equal hashes.
func ShapeText(v any) string {
	b, err := json.Marshal(Shape(v))
	if err != nil {
		return ""
	}
	return sink.Truncate(string(b), maxText)
}

// Redact keeps a command's name and replaces each argument with a key pattern (Redis, Memcached):
// runs of digits and hex ids become `*`, other arguments `?`. Only the first maxArgs are kept.
func Redact(args []string, keyArgs int) string {
	const maxArgs = 8
	if len(args) == 0 {
		return ""
	}
	out := []string{strings.ToUpper(args[0])}
	for i, a := range args[1:] {
		if i >= maxArgs {
			out = append(out, "…")
			break
		}
		if i < keyArgs {
			out = append(out, KeyPattern(a))
		} else {
			out = append(out, "?")
		}
	}
	return strings.Join(out, " ")
}

// KeyPattern turns a key into its pattern: `user:1234:cart` -> `user:*:cart`, `sess:9f8e7d6c5b4a` -> `sess:*`.
// Segments are split on `:`, `/`, `.`, `-` and `_`; a segment holding a digit becomes `*`.
func KeyPattern(k string) string {
	k = sink.Truncate(k, 120)
	var b strings.Builder
	seg := strings.Builder{}
	flush := func() {
		s := seg.String()
		if strings.ContainsAny(s, "0123456789") {
			s = "*"
		}
		b.WriteString(s)
		seg.Reset()
	}
	for _, r := range k {
		if strings.ContainsRune(":/.-_{}", r) {
			flush()
			b.WriteRune(r)
			continue
		}
		seg.WriteRune(r)
	}
	flush()
	return b.String()
}

// EmitSample writes one sample record (event.name `db.<kind>`): kind is query.sample, query.plan, wait,
// keyspace, advice or shard. The payload must already be value-free (BindSafe, Shape, Redact).
func EmitSample(out sink.Sink, system, kind, sev string, payload any, attrs map[string]string, now time.Time) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	a := sink.With(attrs, "db.system.name", system, "event.name", "db."+kind)
	out.Log(sev, sink.Truncate(string(body), maxSample), a, now)
}
