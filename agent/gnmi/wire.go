// Package gnmi is the agent's gNMI streaming telemetry client (INF-016): it subscribes to
// OpenConfig paths on network devices (gNMI Subscribe, STREAM mode, SAMPLE or ON_CHANGE) and
// turns the numeric leaves of every notification into metrics. The gNMI messages it needs are
// encoded and decoded here directly on the protobuf wire format, so no generated code or
// vendored schema is required.
package gnmi

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Elem is one path element with its keys, e.g. interface[name=Ethernet1].
type Elem struct {
	Name string
	Keys map[string]string
}

// Path is a gNMI path.
type Path struct {
	Origin string
	Elems  []Elem
}

// ParsePath reads "origin:/a/b[k=v]/c" (origin optional). Key values may contain '/'.
func ParsePath(s string) (Path, error) {
	var p Path
	if i := strings.Index(s, ":/"); i > 0 && !strings.ContainsAny(s[:i], "/[") {
		p.Origin, s = s[:i], s[i+1:]
	}
	s = strings.TrimPrefix(s, "/")
	if s == "" {
		return p, nil
	}
	var cur strings.Builder
	depth := 0
	var parts []string
	for _, c := range s {
		switch {
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '/' && depth == 0:
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(c)
	}
	if depth != 0 {
		return p, fmt.Errorf("gnmi path %q: unbalanced brackets", s)
	}
	parts = append(parts, cur.String())
	for _, part := range parts {
		e, err := parseElem(part)
		if err != nil {
			return p, err
		}
		p.Elems = append(p.Elems, e)
	}
	return p, nil
}

func parseElem(s string) (Elem, error) {
	name, rest, _ := strings.Cut(s, "[")
	if name == "" {
		return Elem{}, errors.New("gnmi path: empty element")
	}
	e := Elem{Name: name}
	for rest != "" {
		kv, after, ok := strings.Cut(rest, "]")
		if !ok {
			return e, fmt.Errorf("gnmi path element %q: missing ]", s)
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return e, fmt.Errorf("gnmi path element %q: key without =", s)
		}
		if e.Keys == nil {
			e.Keys = map[string]string{}
		}
		e.Keys[k] = v
		rest = strings.TrimPrefix(after, "[")
	}
	return e, nil
}

// String renders the path without keys, e.g. /interfaces/interface/state/oper-status.
func (p Path) String() string {
	var b strings.Builder
	for _, e := range p.Elems {
		b.WriteString("/" + e.Name)
	}
	return b.String()
}

func appendPath(b []byte, num protowire.Number, p Path) []byte {
	var pb []byte
	if p.Origin != "" {
		pb = protowire.AppendTag(pb, 2, protowire.BytesType)
		pb = protowire.AppendString(pb, p.Origin)
	}
	for _, e := range p.Elems {
		var eb []byte
		eb = protowire.AppendTag(eb, 1, protowire.BytesType)
		eb = protowire.AppendString(eb, e.Name)
		keys := make([]string, 0, len(e.Keys))
		for k := range e.Keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var kv []byte
			kv = protowire.AppendTag(kv, 1, protowire.BytesType)
			kv = protowire.AppendString(kv, k)
			kv = protowire.AppendTag(kv, 2, protowire.BytesType)
			kv = protowire.AppendString(kv, e.Keys[k])
			eb = protowire.AppendTag(eb, 2, protowire.BytesType)
			eb = protowire.AppendBytes(eb, kv)
		}
		pb = protowire.AppendTag(pb, 3, protowire.BytesType)
		pb = protowire.AppendBytes(pb, eb)
	}
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, pb)
}

// Subscription modes and encodings of the gNMI specification.
const (
	ModeOnChange = 1
	ModeSample   = 2

	EncodingJSON     = 0
	EncodingProto    = 2
	EncodingJSONIETF = 4
)

// Sub is one subscription of the request.
type Sub struct {
	Path     Path
	Mode     int
	SampleNS uint64
}

// SubscribeRequest encodes SubscribeRequest{subscribe: SubscriptionList{prefix, subscription,
// mode: STREAM, encoding}}.
func SubscribeRequest(prefix Path, subs []Sub, encoding int) []byte {
	var sl []byte
	if prefix.Origin != "" || len(prefix.Elems) > 0 {
		sl = appendPath(sl, 1, prefix)
	}
	for _, s := range subs {
		var sb []byte
		sb = appendPath(sb, 1, s.Path)
		sb = protowire.AppendTag(sb, 2, protowire.VarintType)
		sb = protowire.AppendVarint(sb, uint64(s.Mode)) //nolint:gosec // small enum
		if s.SampleNS > 0 {
			sb = protowire.AppendTag(sb, 3, protowire.VarintType)
			sb = protowire.AppendVarint(sb, s.SampleNS)
		}
		sl = protowire.AppendTag(sl, 2, protowire.BytesType)
		sl = protowire.AppendBytes(sl, sb)
	}
	// mode STREAM is 0, the default, so it is not written
	sl = protowire.AppendTag(sl, 8, protowire.VarintType)
	sl = protowire.AppendVarint(sl, uint64(encoding)) //nolint:gosec // small enum
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	return protowire.AppendBytes(b, sl)
}

// field is one decoded protobuf field: v for varint and fixed types, raw for length-delimited.
type field struct {
	num protowire.Number
	typ protowire.Type
	v   uint64
	raw []byte
}

var errWire = errors.New("gnmi: malformed message")

// fields decodes one message level.
func fields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, errWire
		}
		b = b[n:]
		f := field{num: num, typ: typ}
		switch typ {
		case protowire.VarintType:
			f.v, n = protowire.ConsumeVarint(b)
		case protowire.Fixed32Type:
			var v uint32
			v, n = protowire.ConsumeFixed32(b)
			f.v = uint64(v)
		case protowire.Fixed64Type:
			f.v, n = protowire.ConsumeFixed64(b)
		case protowire.BytesType:
			f.raw, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
		}
		if n < 0 {
			return nil, errWire
		}
		b = b[n:]
		out = append(out, f)
	}
	return out, nil
}

func decodePath(b []byte) (Path, error) {
	fs, err := fields(b)
	if err != nil {
		return Path{}, err
	}
	var p Path
	for _, f := range fs {
		switch f.num {
		case 1: // deprecated string elements
			p.Elems = append(p.Elems, Elem{Name: string(f.raw)})
		case 2:
			p.Origin = string(f.raw)
		case 3:
			es, err := fields(f.raw)
			if err != nil {
				return p, err
			}
			var e Elem
			for _, ef := range es {
				switch ef.num {
				case 1:
					e.Name = string(ef.raw)
				case 2:
					kv, err := fields(ef.raw)
					if err != nil {
						return p, err
					}
					var k, v string
					for _, x := range kv {
						if x.num == 1 {
							k = string(x.raw)
						} else if x.num == 2 {
							v = string(x.raw)
						}
					}
					if e.Keys == nil {
						e.Keys = map[string]string{}
					}
					e.Keys[k] = v
				}
			}
			p.Elems = append(p.Elems, e)
		}
	}
	return p, nil
}

// Value is a decoded TypedValue: Num when it is a number (or a bool, or a JSON number), Str for
// a string.
type Value struct {
	Num   float64
	IsNum bool
	Str   string
}

func decodeValue(b []byte) (Value, error) {
	fs, err := fields(b)
	if err != nil || len(fs) == 0 {
		return Value{}, err
	}
	f := fs[0]
	switch f.num {
	case 1, 12: // string_val, ascii_val
		return Value{Str: string(f.raw)}, nil
	case 2: // int_val
		return Value{Num: float64(int64(f.v)), IsNum: true}, nil //nolint:gosec // two's complement int64
	case 3: // uint_val
		return Value{Num: float64(f.v), IsNum: true}, nil
	case 4: // bool_val
		return Value{Num: float64(f.v & 1), IsNum: true}, nil
	case 6: // float_val (fixed32)
		return Value{Num: float64(math.Float32frombits(uint32(f.v))), IsNum: true}, nil //nolint:gosec // fixed32
	case 14: // double_val
		return Value{Num: math.Float64frombits(f.v), IsNum: true}, nil
	case 7: // decimal_val {digits, precision}
		ds, err := fields(f.raw)
		if err != nil {
			return Value{}, err
		}
		var digits int64
		var prec uint64
		for _, d := range ds {
			if d.num == 1 {
				digits = int64(d.v) //nolint:gosec // int64 field
			} else if d.num == 2 {
				prec = d.v
			}
		}
		return Value{Num: float64(digits) / math.Pow10(int(min(prec, 18))), IsNum: true}, nil //nolint:gosec // bounded
	case 10, 11: // json_val, json_ietf_val: a scalar JSON number or string
		s := strings.Trim(strings.TrimSpace(string(f.raw)), `"`)
		if n, err := strconv.ParseFloat(s, 64); err == nil {
			return Value{Num: n, IsNum: true}, nil
		}
		return Value{Str: s}, nil
	}
	return Value{}, nil
}

// Update is one leaf of a notification, its full path (prefix joined) and value.
type Update struct {
	Path  Path
	Value Value
}

// Notification is a decoded gNMI Notification.
type Notification struct {
	TimestampNS int64
	Updates     []Update
}

// DecodeResponse decodes a SubscribeResponse. sync is true for sync_response; err carries a
// server error message (the deprecated error field).
func DecodeResponse(b []byte, maxUpdates int) (n *Notification, sync bool, err error) {
	fs, err := fields(b)
	if err != nil {
		return nil, false, err
	}
	for _, f := range fs {
		switch f.num {
		case 1:
			n, err = decodeNotification(f.raw, maxUpdates)
			if err != nil {
				return nil, false, err
			}
		case 3:
			sync = f.v != 0
		case 4:
			return nil, false, errors.New("gnmi: the device returned an error")
		}
	}
	return n, sync, nil
}

func decodeNotification(b []byte, maxUpdates int) (*Notification, error) {
	fs, err := fields(b)
	if err != nil {
		return nil, err
	}
	n := &Notification{}
	var prefix Path
	var ups [][]byte
	for _, f := range fs {
		switch f.num {
		case 1:
			n.TimestampNS = int64(f.v) //nolint:gosec // int64 field
		case 2:
			if prefix, err = decodePath(f.raw); err != nil {
				return nil, err
			}
		case 4:
			if len(ups) < maxUpdates {
				ups = append(ups, f.raw)
			}
		}
	}
	for _, u := range ups {
		ufs, err := fields(u)
		if err != nil {
			return nil, err
		}
		var up Update
		for _, f := range ufs {
			switch f.num {
			case 1:
				p, err := decodePath(f.raw)
				if err != nil {
					return nil, err
				}
				up.Path = Path{Origin: prefix.Origin, Elems: append(append([]Elem(nil), prefix.Elems...), p.Elems...)}
			case 3:
				if up.Value, err = decodeValue(f.raw); err != nil {
					return nil, err
				}
			}
		}
		n.Updates = append(n.Updates, up)
	}
	return n, nil
}
