package relay

import (
	"encoding/hex"
	"sort"
	"strconv"

	"google.golang.org/protobuf/encoding/protowire"
)

// ddAgentPayload encodes spans as the trace-agent's /api/v0.2/traces AgentPayload, the inverse of
// the gateway's receiver (go/gateway/push_datadog_pb.go, same field numbers): one TracerPayload
// holding one TraceChunk per trace. A 128-bit trace id keeps its high half in meta `_dd.p.tid`.
func ddAgentPayload(spans []Event, host string) []byte {
	byTrace := map[string][]Event{}
	var order []string
	for _, e := range spans {
		if _, ok := byTrace[e.TraceID]; !ok {
			order = append(order, e.TraceID)
		}
		byTrace[e.TraceID] = append(byTrace[e.TraceID], e)
	}
	var tp []byte
	for _, id := range order {
		var chunk []byte
		chunk = protowire.AppendTag(chunk, 1, protowire.VarintType) // priority: auto keep
		chunk = protowire.AppendVarint(chunk, 1)
		for _, e := range byTrace[id] {
			chunk = protowire.AppendTag(chunk, 3, protowire.BytesType)
			chunk = protowire.AppendBytes(chunk, ddSpanPB(e))
		}
		tp = protowire.AppendTag(tp, 6, protowire.BytesType)
		tp = protowire.AppendBytes(tp, chunk)
	}
	if host != "" {
		tp = protowire.AppendTag(tp, 9, protowire.BytesType)
		tp = protowire.AppendString(tp, host)
	}
	var out []byte
	if host != "" {
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendString(out, host)
	}
	out = protowire.AppendTag(out, 5, protowire.BytesType)
	return protowire.AppendBytes(out, tp)
}

func hexU64(s string) uint64 { // low 64 bits of a hex id
	if len(s) > 16 {
		s = s[len(s)-16:]
	}
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}

func ddSpanPB(e Event) []byte {
	str := func(b []byte, n protowire.Number, v string) []byte {
		b = protowire.AppendTag(b, n, protowire.BytesType)
		return protowire.AppendString(b, v)
	}
	num := func(b []byte, n protowire.Number, v uint64) []byte {
		b = protowire.AppendTag(b, n, protowire.VarintType)
		return protowire.AppendVarint(b, v)
	}
	res, typ := e.Attrs["resource.name"], e.Attrs["dd.span.type"]
	if res == "" {
		res = e.Name
	}
	if typ == "" {
		typ = "custom"
	}
	var b []byte
	b = str(b, 1, e.Service)
	b = str(b, 2, e.Name)
	b = str(b, 3, res)
	b = num(b, 4, hexU64(e.TraceID))
	b = num(b, 5, hexU64(e.SpanID))
	b = num(b, 6, hexU64(e.ParentID))
	b = num(b, 7, uint64(e.Time.UnixNano()))
	b = num(b, 8, uint64(max(e.DurationNs, 0)))
	if e.Error {
		b = num(b, 9, 1)
	}
	meta := map[string]string{}
	for k, v := range e.Attrs {
		if k != "resource.name" && k != "dd.span.type" {
			meta[k] = v
		}
	}
	if len(e.TraceID) > 16 {
		if hi, err := hex.DecodeString(e.TraceID[:len(e.TraceID)-16]); err == nil && len(hi) == 8 {
			meta["_dd.p.tid"] = e.TraceID[:len(e.TraceID)-16]
		}
	}
	if e.Error && e.Message != "" {
		meta["error.msg"] = e.Message
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var ent []byte
		ent = str(ent, 1, k)
		ent = str(ent, 2, meta[k])
		b = protowire.AppendTag(b, 10, protowire.BytesType)
		b = protowire.AppendBytes(b, ent)
	}
	b = str(b, 12, typ)
	return b
}
