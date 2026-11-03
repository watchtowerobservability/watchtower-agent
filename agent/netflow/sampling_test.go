package netflow

import "testing"

// v9 options template 300: scope system(1, 4 bytes), options samplerId(48, 1), samplingInterval(34, 4).
func v9OptionsTemplate() []byte {
	var b buf
	b.u16(1).u16(4 + 6 + 12).u16(300).u16(4).u16(8)
	b.u16(1).u16(4).u16(48).u16(1).u16(34).u16(4)
	return b
}

func v9OptionsData(sampler uint8, rate uint32) []byte {
	var b buf
	b.u16(300).u16(4 + 9).u32(0).u8(sampler).u32(rate)
	return b
}

func TestV9OptionsSamplingScalesCounters(t *testing.T) {
	c := NewTemplates()
	if _, _, err := c.DecodeV9("r1", v9Packet(templateSet(0), v9OptionsTemplate())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.DecodeV9("r1", v9Packet(v9OptionsData(0, 100))); err != nil {
		t.Fatal(err)
	}
	fl, _, err := c.DecodeV9("r1", v9Packet(dataSet()))
	if err != nil || len(fl) != 1 || fl[0].Bytes != 90_000 || fl[0].Packets != 300 {
		t.Fatalf("flows %+v err %v", fl, err)
	}
	// another exporter is not scaled by r1's rate
	_, _, _ = c.DecodeV9("r2", v9Packet(templateSet(0)))
	if fl, _, _ := c.DecodeV9("r2", v9Packet(dataSet())); len(fl) != 1 || fl[0].Bytes != 900 {
		t.Fatalf("r2 %+v", fl)
	}
}

func TestIPFIXRecordSamplingIntervalWins(t *testing.T) {
	c := NewTemplates()
	var tm buf // template 257: src, dst, bytes(4), packets(4), samplingPacketInterval(305, 4)
	tm.u16(2).u16(4 + 4 + 4*5).u16(257).u16(5)
	for _, f := range [][2]uint16{{8, 4}, {12, 4}, {1, 4}, {2, 4}, {305, 4}} {
		tm.u16(f[0]).u16(f[1])
	}
	var ds buf
	ds.u16(257).u16(4 + 20).raw(ip4("10.0.0.1")).raw(ip4("10.0.0.2")).u32(10).u32(1).u32(64)
	fl, _, err := c.DecodeIPFIX("r1", ipfixMsg(tm, ds))
	if err != nil || len(fl) != 1 || fl[0].Bytes != 640 || fl[0].Packets != 64 {
		t.Fatalf("flows %+v err %v", fl, err)
	}
}

func TestSamplerIDFallsBackToExporterRate(t *testing.T) {
	var s samplers
	s.set(skey{"r", 1, 0}, 10)
	s.set(skey{"r", 1, 7}, 50)
	if s.get(skey{"r", 1, 7}) != 50 || s.get(skey{"r", 1, 9}) != 10 || s.get(skey{"x", 1, 0}) != 0 {
		t.Fatal("lookup order")
	}
	s.set(skey{"r", 1, 8}, 1<<30) // absurd rate ignored
	if s.get(skey{"r", 1, 8}) != 10 {
		t.Fatal("absurd rate accepted")
	}
}
