package netflow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

type buf []byte

func (b *buf) u8(v ...uint8) *buf { *b = append(*b, v...); return b }
func (b *buf) u16(v uint16) *buf  { *b = binary.BigEndian.AppendUint16(*b, v); return b }
func (b *buf) u32(v uint32) *buf  { *b = binary.BigEndian.AppendUint32(*b, v); return b }
func (b *buf) raw(v []byte) *buf  { *b = append(*b, v...); return b }

func ip4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }

func v5Packet() []byte {
	var b buf
	b.u16(5).u16(2).u32(1000).u32(1700000000).u32(0).u32(1).u8(0, 0).u16(0)
	rec := func(src, dst string, in, out uint16, pk, by uint32, sp, dp uint16, proto uint8) {
		b.raw(ip4(src)).raw(ip4(dst)).u32(0).u16(in).u16(out).u32(pk).u32(by).u32(0).u32(0)
		b.u16(sp).u16(dp).u8(0, 0, proto, 0).u16(0).u16(0).u16(0).u16(0)
	}
	rec("10.0.0.1", "10.0.0.2", 1, 2, 10, 1500, 443, 51000, 6)
	rec("10.0.0.3", "10.0.0.4", 3, 4, 1, 80, 53, 5353, 17)
	return b
}

func TestNetflowV5Decode(t *testing.T) {
	pkt := v5Packet()
	if len(pkt) != 24+2*48 {
		t.Fatalf("fixture length %d", len(pkt))
	}
	fl, err := DecodeV5(pkt)
	if err != nil || len(fl) != 2 {
		t.Fatalf("flows %v err %v", fl, err)
	}
	f := fl[0]
	if f.Src.String() != "10.0.0.1" || f.Dst.String() != "10.0.0.2" || f.Bytes != 1500 || f.Packets != 10 ||
		f.SrcPort != 443 || f.DstPort != 51000 || f.Proto != 6 || f.InIf != 1 || f.OutIf != 2 {
		t.Fatalf("flow %+v", f)
	}
	if _, err := DecodeV5(pkt[:len(pkt)-1]); err == nil {
		t.Fatal("a truncated packet must be refused")
	}
}

// template 256: src v4, dst v4, bytes(4), packets(4), proto, sport, dport, in, out
var tmplFields = [][2]uint16{{8, 4}, {12, 4}, {1, 4}, {2, 4}, {4, 1}, {7, 2}, {11, 2}, {10, 4}, {14, 4}}

func templateSet(setID uint16) []byte {
	var b buf
	b.u16(setID).u16(uint16(4 + 4 + 4*len(tmplFields))).u16(256).u16(uint16(len(tmplFields)))
	for _, f := range tmplFields {
		b.u16(f[0]).u16(f[1])
	}
	return b
}

func dataSet() []byte {
	var b buf
	b.u16(256).u16(4 + 29)
	b.raw(ip4("192.168.1.10")).raw(ip4("8.8.8.8")).u32(900).u32(3).u8(17).u16(5000).u16(53).u32(7).u32(8)
	return b
}

func v9Packet(sets ...[]byte) []byte {
	var b buf
	b.u16(9).u16(uint16(len(sets))).u32(1).u32(1700000000).u32(1).u32(42)
	for _, s := range sets {
		b.raw(s)
	}
	return b
}

func ipfixMsg(sets ...[]byte) []byte {
	var b buf
	n := 16
	for _, s := range sets {
		n += len(s)
	}
	b.u16(10).u16(uint16(n)).u32(1700000000).u32(1).u32(42)
	for _, s := range sets {
		b.raw(s)
	}
	return b
}

func TestNetflowV9TemplateThenData(t *testing.T) {
	c := NewTemplates()
	fl, miss, err := c.DecodeV9("10.1.1.1", v9Packet(dataSet()))
	if err != nil || len(fl) != 0 || miss != 1 {
		t.Fatalf("data before its template is skipped and counted: %v %d %v", fl, miss, err)
	}
	if _, _, err := c.DecodeV9("10.1.1.1", v9Packet(templateSet(0))); err != nil || c.Len() != 1 {
		t.Fatalf("template: %v len %d", err, c.Len())
	}
	fl, miss, err = c.DecodeV9("10.1.1.1", v9Packet(dataSet()))
	if err != nil || miss != 0 || len(fl) != 1 {
		t.Fatalf("flows %v miss %d err %v", fl, miss, err)
	}
	f := fl[0]
	if f.Src.String() != "192.168.1.10" || f.Dst.String() != "8.8.8.8" || f.Bytes != 900 || f.Packets != 3 ||
		f.Proto != 17 || f.SrcPort != 5000 || f.DstPort != 53 || f.InIf != 7 || f.OutIf != 8 {
		t.Fatalf("flow %+v", f)
	}
	// another exporter does not share the template
	if _, miss, _ := c.DecodeV9("10.9.9.9", v9Packet(dataSet())); miss != 1 {
		t.Fatal("templates are per exporter")
	}
}

func TestIPFIXDecode(t *testing.T) {
	c := NewTemplates()
	fl, miss, err := c.DecodeIPFIX("10.1.1.1", ipfixMsg(templateSet(2), dataSet()))
	if err != nil || miss != 0 || len(fl) != 1 || fl[0].Bytes != 900 || fl[0].Dst.String() != "8.8.8.8" {
		t.Fatalf("flows %v miss %d err %v", fl, miss, err)
	}
	msg := ipfixMsg(dataSet())
	binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)+10)) // length beyond the datagram
	if _, _, err := c.DecodeIPFIX("10.1.1.1", msg); err == nil {
		t.Fatal("an overlong length must be refused")
	}
}

func sflowDatagram() []byte {
	var frame buf // ethernet + ipv4 + tcp header
	frame.raw(make([]byte, 12)).u16(0x0800)
	frame.u8(0x45, 0).u16(1400).u32(0).u8(64, 6).u16(0).raw(ip4("172.16.0.1")).raw(ip4("172.16.0.2"))
	frame.u16(8080).u16(443).raw(make([]byte, 16))
	var rec buf
	rec.u32(1).u32(1400).u32(0).u32(uint32(len(frame))).raw(frame)
	var fs buf // flow sample: seq, source, rate, pool, drops, in, out, nrecords
	fs.u32(1).u32(0).u32(100).u32(0).u32(0).u32(5).u32(6).u32(1)
	fs.u32(1).u32(uint32(len(rec))).raw(rec)
	var b buf
	b.u32(5).u32(1).raw(ip4("10.0.0.254")).u32(0).u32(1).u32(1000).u32(1)
	b.u32(1).u32(uint32(len(fs))).raw(fs)
	return b
}

func TestSFlowV5Decode(t *testing.T) {
	fl, err := DecodeSFlow(sflowDatagram())
	if err != nil || len(fl) != 1 {
		t.Fatalf("flows %v err %v", fl, err)
	}
	f := fl[0]
	if f.Src.String() != "172.16.0.1" || f.Dst.String() != "172.16.0.2" || f.SrcPort != 8080 || f.DstPort != 443 ||
		f.Proto != 6 || f.Bytes != 140000 || f.Packets != 100 || f.InIf != 5 || f.OutIf != 6 {
		t.Fatalf("flow %+v", f)
	}
}

func TestCollectorNeverPanicsOnTruncation(t *testing.T) {
	c := New()
	from := netip.MustParseAddr("10.1.1.1")
	for _, p := range [][]byte{v5Packet(), v9Packet(templateSet(0), dataSet()), ipfixMsg(templateSet(2), dataSet()), sflowDatagram()} {
		for n := 0; n <= len(p); n++ {
			c.Handle(from, p[:n], time.Now())
		}
		for i := range p { // single-byte corruption
			q := append([]byte(nil), p...)
			q[i] ^= 0xff
			c.Handle(from, q, time.Now())
		}
	}
	c.Handle(from, make([]byte, MaxPacket+1), time.Now())
	if c.Stats.Oversize.Load() != 1 || c.Stats.Malformed.Load() == 0 {
		t.Fatalf("stats %d %d", c.Stats.Oversize.Load(), c.Stats.Malformed.Load())
	}
}

func TestTemplateCacheBounds(t *testing.T) {
	c := NewTemplates()
	tm := &template{fields: []field{{ieBytes, 4}}, recLen: 4}
	for i := range 2 * MaxTemplatesPerExporter {
		c.put(tkey{exporter: "a", id: uint16(256 + i)}, tm)
	}
	if c.Len() != MaxTemplatesPerExporter {
		t.Fatalf("per exporter: %d", c.Len())
	}
	for e := range MaxTemplates / MaxTemplatesPerExporter * 2 {
		for i := range MaxTemplatesPerExporter {
			c.put(tkey{exporter: string(rune('b' + e)), id: uint16(256 + i)}, tm)
		}
	}
	if c.Len() > MaxTemplates {
		t.Fatalf("total: %d", c.Len())
	}
	for e := range MaxExporters + 10 {
		c.put(tkey{exporter: "x" + time.Duration(e).String(), id: 256}, tm)
	}
	if len(c.exps) > MaxExporters || c.Evicted() == 0 {
		t.Fatalf("exporters: %d evicted %d", len(c.exps), c.Evicted())
	}
	// the newest exporter is cached: a new router is never refused
	if c.get(tkey{exporter: "x" + time.Duration(MaxExporters+9).String(), id: 256}) == nil {
		t.Fatal("the most recent exporter must be cached")
	}
}

func zeroFieldTemplate(setID uint16) []byte {
	var b buf
	b.u16(setID).u16(8).u16(256).u16(0)
	return b
}

func TestZeroLengthTemplateIsRejected(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		c := NewTemplates()
		fl, miss, err := c.DecodeV9("10.1.1.1", v9Packet(zeroFieldTemplate(0), dataSet()))
		if err == nil || len(fl) != 0 || miss != 1 || c.Len() != 0 {
			t.Errorf("v9: flows %v miss %d err %v len %d", fl, miss, err, c.Len())
		}
		fl, miss, _ = c.DecodeIPFIX("10.1.1.2", ipfixMsg(zeroFieldTemplate(2), dataSet()))
		if len(fl) != 0 || miss != 1 || c.Len() != 0 {
			t.Errorf("ipfix: flows %v miss %d len %d", fl, miss, c.Len())
		}
		if decodeData(&template{}, make([]byte, 64)) != nil {
			t.Error("a zero-length template must not decode")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("decoder did not return")
	}
}

func TestAggregatorBoundsExporters(t *testing.T) {
	a := NewAggregator()
	at := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	for i := range MaxAggExporters + 5 {
		a.Add(Flow{Exporter: time.Duration(i).String(), Bytes: 1, Packets: 1,
			Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2")}, at)
	}
	if len(a.open[at]) > MaxAggExporters || a.Evicted() != 5 {
		t.Fatalf("exporters %d evicted %d", len(a.open[at]), a.Evicted())
	}
}

func TestFlowTopNAggregation(t *testing.T) {
	a := NewAggregator()
	at := time.Date(2026, 1, 1, 10, 0, 30, 0, time.UTC)
	var total uint64
	for i := range 1500 {
		f := Flow{Exporter: "r1", Src: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}),
			Dst: netip.MustParseAddr("10.9.9.9"), Proto: 6, Bytes: uint64(i + 1), Packets: 1}
		total += f.Bytes
		a.Add(f, at)
	}
	var rec sink.Recorder
	a.Flush(at, false, &rec) // the minute is still open
	if len(rec.Samples) != 0 {
		t.Fatal("an open minute must not flush")
	}
	a.Flush(at.Add(time.Minute), false, &rec)
	if len(rec.Samples) != MaxConversations+1 {
		t.Fatalf("rows: %d", len(rec.Samples))
	}
	var sum, others int
	for _, s := range rec.Samples {
		var by int
		for _, c := range s.Attrs["flow.bytes"] {
			by = by*10 + int(c-'0')
		}
		sum += by
		if s.Attrs["flow.src_ip"] == "::" {
			others++
		}
	}
	if sum != int(total) || others != 1 {
		t.Fatalf("bytes %d want %d, other rows %d", sum, total, others)
	}
}
