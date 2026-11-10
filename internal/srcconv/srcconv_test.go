package srcconv

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestMsgpackStreamAndExt(t *testing.T) {
	// fixext8 type 0 (EventTime: sec 10, nsec 5) then a fixstr
	b := []byte{0xd7, 0x00, 0, 0, 0, 10, 0, 0, 0, 5, 0xa1, 'x'}
	v, rest, err := MsgpackNext(b, true)
	if err != nil || v.(time.Time).Unix() != 10 || v.(time.Time).Nanosecond() != 5 {
		t.Fatalf("%v %v", v, err)
	}
	if s, _, err := MsgpackNext(rest, true); err != nil || s != "x" {
		t.Fatalf("%v %v", s, err)
	}
	if _, _, err := MsgpackNext(b, false); err == nil {
		t.Fatal("ext accepted without the flag")
	}
	if _, _, err := MsgpackNext([]byte{0xa3, 'a'}, true); !errors.Is(err, ErrMsgpackShort) {
		t.Fatalf("truncated string: %v", err)
	}
	if _, _, err := MsgpackNext([]byte{0x92, 0x01}, true); !errors.Is(err, ErrMsgpackShort) {
		t.Fatalf("truncated array: %v", err)
	}
	if _, err := MsgpackDecode([]byte{0xc1}); err == nil || errors.Is(err, ErrMsgpackShort) {
		t.Fatalf("invalid byte: %v", err)
	}
}

func TestSeriesFromProto(t *testing.T) {
	var pt []byte
	pt = protowire.AppendTag(pt, 1, protowire.Fixed64Type)
	pt = protowire.AppendFixed64(pt, 0x4008000000000000) // 3.0
	pt = protowire.AppendTag(pt, 2, protowire.VarintType)
	pt = protowire.AppendVarint(pt, 1700000000)
	var res []byte
	res = protowire.AppendTag(res, 1, protowire.BytesType)
	res = protowire.AppendString(res, "host")
	res = protowire.AppendTag(res, 2, protowire.BytesType)
	res = protowire.AppendString(res, "h9")
	var s []byte
	s = protowire.AppendTag(s, 1, protowire.BytesType)
	s = protowire.AppendBytes(s, res)
	s = protowire.AppendTag(s, 2, protowire.BytesType)
	s = protowire.AppendString(s, "m.x")
	s = protowire.AppendTag(s, 3, protowire.BytesType)
	s = protowire.AppendString(s, "env:p")
	s = protowire.AppendTag(s, 4, protowire.BytesType)
	s = protowire.AppendBytes(s, pt)
	s = protowire.AppendTag(s, 5, protowire.VarintType)
	s = protowire.AppendVarint(s, 1)
	var top []byte
	top = protowire.AppendTag(top, 1, protowire.BytesType)
	top = protowire.AppendBytes(top, s)
	got, err := SeriesFromProto(top)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	m := got[0].OTLP()
	if got[0].Kind() != "count" || m.Name != "m.x" || m.GetSum().DataPoints[0].GetAsDouble() != 3 || got[0].Resources[0].Name != "h9" {
		t.Fatalf("%+v %v", got[0], m)
	}
	if _, err := SeriesFromProto([]byte{0xff}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestHECDecodeAndLimit(t *testing.T) {
	evs, err := HECDecode([]byte(`{"event":"a"}{"event":{"k":1}}`), 10)
	if err != nil || len(evs) != 2 {
		t.Fatalf("%v %v", evs, err)
	}
	if _, err := HECDecode([]byte(`{"event":"a"}{"event":"b"}`), 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
	if _, err := HECDecode([]byte(`{"x":1}`), 10); !errors.Is(err, ErrHECFormat) {
		t.Fatalf("%v", err)
	}
	l, m := HECRequests(evs, 5)
	if m != nil || len(l.ResourceLogs[0].ScopeLogs[0].LogRecords) != 2 {
		t.Fatalf("%v %v", l, m)
	}
	svc, _ := HECDecode([]byte(`{"event":"a","fields":{"service":"checkout"}}{"event":"b","service":"cart"}{"event":"c"}`), 10)
	l, _ = HECRequests(svc, 5)
	got := map[string]int{}
	for _, rl := range l.ResourceLogs {
		name := ""
		for _, kv := range rl.Resource.Attributes {
			if kv.Key == "service.name" {
				name = kv.Value.GetStringValue()
			}
		}
		got[name] += len(rl.ScopeLogs[0].LogRecords)
	}
	if got["checkout"] != 1 || got["cart"] != 1 || got[""] != 1 || HECLogCount(l) != 3 {
		t.Fatalf("service.name per resource: %v", got)
	}
}
