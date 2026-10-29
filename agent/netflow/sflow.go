package netflow

import "net/netip"

const (
	sflowFlowSample     = 1
	sflowExpandedSample = 3
	sflowRawHeader      = 1
	maxSamples          = 1_000
)

// DecodeSFlow decodes an sFlow v5 datagram. Only flow samples with a raw packet header record
// are read; the counters are scaled by the sampling rate (bytes = frame length x rate).
func DecodeSFlow(b []byte) ([]Flow, error) {
	if len(b) < 28 || be32(b) != 5 {
		return nil, ErrMalformed
	}
	off := 8
	switch be32(b[4:]) { // agent address type
	case 1:
		off += 4
	case 2:
		off += 16
	default:
		return nil, ErrMalformed
	}
	if len(b) < off+16 {
		return nil, ErrMalformed
	}
	n := int(be32(b[off+12:]))
	b = b[off+16:]
	var out []Flow
	for i := 0; i < n && i < maxSamples; i++ {
		if len(b) < 8 {
			return out, ErrMalformed
		}
		tag, ln := be32(b), int(be32(b[4:]))
		if ln < 0 || ln > len(b)-8 {
			return out, ErrMalformed
		}
		body := b[8 : 8+ln]
		b = b[8+ln:]
		if tag == sflowFlowSample || tag == sflowExpandedSample {
			out = append(out, flowSample(body, tag == sflowExpandedSample)...)
		}
	}
	return out, nil
}

func flowSample(b []byte, expanded bool) []Flow {
	// seq, source, rate, pool, drops, input, output, records (expanded has 2 words per interface)
	words := 8
	if expanded {
		words = 11
	}
	if len(b) < words*4 {
		return nil
	}
	var rate, in, outIf uint32
	if expanded {
		rate, in, outIf = be32(b[12:]), be32(b[28:]), be32(b[36:])
	} else {
		rate, in, outIf = be32(b[8:]), be32(b[20:]), be32(b[24:])
	}
	n := int(be32(b[(words-1)*4:]))
	b = b[words*4:]
	rate = max(rate, 1)
	var out []Flow
	for i := 0; i < n && i < 16; i++ {
		if len(b) < 8 {
			break
		}
		tag, ln := be32(b), int(be32(b[4:]))
		if ln < 0 || ln > len(b)-8 {
			break
		}
		rec := b[8 : 8+ln]
		b = b[8+ln:]
		if tag != sflowRawHeader || len(rec) < 16 || be32(rec) != 1 { // 1: ethernet
			continue
		}
		frame, hl := uint64(be32(rec[4:])), int(be32(rec[12:]))
		if hl < 0 || hl > len(rec)-16 {
			continue
		}
		f, ok := parseEthernet(rec[16 : 16+hl])
		if !ok {
			continue
		}
		f.Bytes, f.Packets = frame*uint64(rate), uint64(rate)
		f.InIf, f.OutIf = in, outIf
		if !expanded { // compact samples pack a format into the top two bits
			f.InIf, f.OutIf = in&0x3fffffff, outIf&0x3fffffff
		}
		out = append(out, f)
	}
	return out
}

// parseEthernet reads addresses, protocol and ports from a sampled frame header.
func parseEthernet(p []byte) (Flow, bool) {
	var f Flow
	if len(p) < 14 {
		return f, false
	}
	et, p := be16(p[12:]), p[14:]
	for et == 0x8100 && len(p) >= 4 { // 802.1Q
		et, p = be16(p[2:]), p[4:]
	}
	var l4 []byte
	switch {
	case et == 0x0800 && len(p) >= 20 && p[0]>>4 == 4:
		ihl := int(p[0]&0xf) * 4
		if ihl < 20 || len(p) < ihl {
			return f, false
		}
		f.Src, f.Dst = netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
		f.Proto, l4 = p[9], p[ihl:]
	case et == 0x86dd && len(p) >= 40:
		f.Src, f.Dst = netip.AddrFrom16([16]byte(p[8:24])).Unmap(), netip.AddrFrom16([16]byte(p[24:40])).Unmap()
		f.Proto, l4 = p[6], p[40:]
	default:
		return f, false
	}
	if (f.Proto == 6 || f.Proto == 17) && len(l4) >= 4 {
		f.SrcPort, f.DstPort = be16(l4), be16(l4[2:])
	}
	return f, true
}
