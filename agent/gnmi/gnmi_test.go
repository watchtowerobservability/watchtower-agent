package gnmi

import (
	"math"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestParsePathKeysAndOrigin(t *testing.T) {
	p, err := ParsePath("openconfig:/interfaces/interface[name=Ethernet1/1]/state/counters")
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != "openconfig" || len(p.Elems) != 4 || p.Elems[1].Keys["name"] != "Ethernet1/1" || p.String() != "/interfaces/interface/state/counters" {
		t.Fatalf("%+v", p)
	}
	if _, err := ParsePath("/a[k=v"); err == nil {
		t.Fatal("unbalanced accepted")
	}
}

func TestSubscribeRequestRoundTrips(t *testing.T) {
	p, _ := ParsePath("/interfaces/interface[name=eth0]/state")
	b := SubscribeRequest(Path{}, []Sub{{Path: p, Mode: ModeSample, SampleNS: 30e9}}, EncodingJSONIETF)
	top, err := fields(b)
	if err != nil || len(top) != 1 || top[0].num != 1 {
		t.Fatalf("%v %+v", err, top)
	}
	sl, _ := fields(top[0].raw)
	var sub []byte
	var enc uint64
	for _, f := range sl {
		switch f.num {
		case 2:
			sub = f.raw
		case 8:
			enc = f.v
		}
	}
	if enc != EncodingJSONIETF || sub == nil {
		t.Fatalf("list %+v", sl)
	}
	sf, _ := fields(sub)
	got, _ := decodePath(sf[0].raw)
	if got.Elems[1].Keys["name"] != "eth0" || sf[1].v != ModeSample || sf[2].v != 30e9 {
		t.Fatalf("sub %+v path %+v", sf, got)
	}
}

func elem(name string, keys ...string) []byte {
	var e []byte
	e = protowire.AppendTag(e, 1, protowire.BytesType)
	e = protowire.AppendString(e, name)
	for i := 0; i+1 < len(keys); i += 2 {
		var kv []byte
		kv = protowire.AppendTag(kv, 1, protowire.BytesType)
		kv = protowire.AppendString(kv, keys[i])
		kv = protowire.AppendTag(kv, 2, protowire.BytesType)
		kv = protowire.AppendString(kv, keys[i+1])
		e = protowire.AppendTag(e, 2, protowire.BytesType)
		e = protowire.AppendBytes(e, kv)
	}
	return e
}

func path(elems ...[]byte) []byte {
	var p []byte
	for _, e := range elems {
		p = protowire.AppendTag(p, 3, protowire.BytesType)
		p = protowire.AppendBytes(p, e)
	}
	return p
}

func update(p, val []byte) []byte {
	var u []byte
	u = protowire.AppendTag(u, 1, protowire.BytesType)
	u = protowire.AppendBytes(u, p)
	u = protowire.AppendTag(u, 3, protowire.BytesType)
	return protowire.AppendBytes(u, val)
}

func TestDecodeNotificationAndEmit(t *testing.T) {
	var uintVal, strVal, dblVal []byte
	uintVal = protowire.AppendTag(uintVal, 3, protowire.VarintType)
	uintVal = protowire.AppendVarint(uintVal, 12345)
	strVal = protowire.AppendTag(strVal, 1, protowire.BytesType)
	strVal = protowire.AppendString(strVal, "UP")
	dblVal = protowire.AppendTag(dblVal, 14, protowire.Fixed64Type)
	dblVal = protowire.AppendFixed64(dblVal, math.Float64bits(41.5))
	var n []byte
	n = protowire.AppendTag(n, 1, protowire.VarintType)
	n = protowire.AppendVarint(n, 1_700_000_000_000_000_000)
	n = protowire.AppendTag(n, 2, protowire.BytesType)
	n = protowire.AppendBytes(n, path(elem("interfaces"), elem("interface", "name", "eth0"), elem("state")))
	for _, u := range [][]byte{
		update(path(elem("counters"), elem("in-octets")), uintVal),
		update(path(elem("oper-status")), strVal),
		update(path(elem("temperature")), dblVal),
	} {
		n = protowire.AppendTag(n, 4, protowire.BytesType)
		n = protowire.AppendBytes(n, u)
	}
	var resp []byte
	resp = protowire.AppendTag(resp, 1, protowire.BytesType)
	resp = protowire.AppendBytes(resp, n)
	got, _, err := DecodeResponse(resp, 100)
	if err != nil || got == nil || len(got.Updates) != 3 {
		t.Fatalf("%v %+v", err, got)
	}
	rec := &sink.Recorder{}
	Emit(rec, map[string]string{"gnmi.target": "leaf1"}, got)
	want := map[string]float64{
		"gnmi.interfaces.interface.state.counters.in_octets": 12345,
		"gnmi.interfaces.interface.state.oper_status":        1,
		"gnmi.interfaces.interface.state.temperature":        41.5,
	}
	for _, s := range rec.Samples {
		if w, ok := want[s.Name]; !ok || w != s.Value || s.Attrs["gnmi.interface.name"] != "eth0" {
			t.Fatalf("%+v", s)
		}
		delete(want, s.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing %v", want)
	}
	var sync []byte
	sync = protowire.AppendTag(sync, 3, protowire.VarintType)
	sync = protowire.AppendVarint(sync, 1)
	if n, s, err := DecodeResponse(sync, 1); err != nil || !s || n != nil {
		t.Fatal("sync_response")
	}
	if _, _, err := DecodeResponse([]byte{0x0a, 0x05, 0x01}, 1); err == nil {
		t.Fatal("truncated message accepted")
	}
}

func TestCredentialsRefusedWithoutTLS(t *testing.T) {
	tg := Target{Name: "x", Address: "10.0.0.1:6030", Plaintext: true, Username: "u", Paths: []string{"/a"}}
	if _, err := tg.dialOptions(); err == nil {
		t.Fatal("credentials over plaintext accepted")
	}
	tg.Username = ""
	if _, err := tg.dialOptions(); err != nil {
		t.Fatal(err)
	}
	tg.Mode = "poll"
	if _, err := tg.request(); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
