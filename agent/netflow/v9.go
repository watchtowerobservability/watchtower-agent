package netflow

const (
	v9HeaderLen    = 20
	maxFields      = 128
	maxRecLen      = 4096
	unknownField   = 0xffff
	varLen         = 0xffff
	enterpriseFlag = 0x8000
)

// IANA information element ids shared by NetFlow v9 and IPFIX.
const (
	ieBytes   = 1
	iePackets = 2
	ieProto   = 4
	ieSrcPort = 7
	ieSrcV4   = 8
	ieInIf    = 10
	ieDstPort = 11
	ieDstV4   = 12
	ieOutIf   = 14
	ieSrcV6   = 27
	ieDstV6   = 28
)

// DecodeV9 decodes a NetFlow v9 packet from exporter. Data sets whose template is not known yet
// are skipped; the second return value counts them.
func (c *Templates) DecodeV9(exporter string, b []byte) ([]Flow, int, error) {
	if len(b) < v9HeaderLen || be16(b) != 9 {
		return nil, 0, ErrMalformed
	}
	return c.decodeSets(exporter, be32(b[16:]), b[v9HeaderLen:], false)
}

// decodeSets walks the flow sets of a v9 packet or the sets of an IPFIX message.
func (c *Templates) decodeSets(exporter string, domain uint32, b []byte, ipfix bool) ([]Flow, int, error) {
	tmplID, optID := uint16(0), uint16(1)
	if ipfix {
		tmplID, optID = 2, 3
	}
	var out []Flow
	missing, bad := 0, 0
	for len(b) > 0 {
		if len(b) < 4 {
			return out, missing, ErrMalformed
		}
		id, ln := be16(b), int(be16(b[2:]))
		if ln < 4 || ln > len(b) {
			return out, missing, ErrMalformed
		}
		body := b[4:ln]
		b = b[ln:]
		switch {
		case id == tmplID:
			bad += c.parseTemplates(tkey{exporter: exporter, domain: domain, ipfix: ipfix}, body)
		case id == optID:
			bad += c.parseOptionTemplates(tkey{exporter: exporter, domain: domain, ipfix: ipfix}, body)
		case id < 256:
		default:
			t := c.get(tkey{exporter, domain, id, ipfix})
			if t == nil {
				missing++
				continue
			}
			if t.option {
				c.optionRecords(exporter, domain, t, body)
				continue
			}
			out = append(out, decodeRecords(t, body, func(f *Flow, sp sampling) { c.scale(exporter, domain, f, sp) })...)
		}
	}
	if bad > 0 { // flows already decoded are kept; the packet is counted as malformed
		return out, missing, ErrMalformed
	}
	return out, missing, nil
}

// parseTemplates reads the template records of a template set. A template that is malformed or
// uses variable-length fields is ignored; an IPFIX template with zero fields withdraws it.
func (c *Templates) parseTemplates(base tkey, b []byte) (bad int) {
	for len(b) >= 4 {
		id, n := be16(b), int(be16(b[2:]))
		b = b[4:]
		if n > maxFields {
			return bad + 1
		}
		t := &template{}
		ok := id >= 256
		for range n {
			if len(b) < 4 {
				return bad + 1
			}
			typ, ln := be16(b), int(be16(b[2:]))
			b = b[4:]
			if base.ipfix && typ&enterpriseFlag != 0 {
				if len(b) < 4 {
					return bad + 1
				}
				b, typ = b[4:], unknownField
			}
			if ln == 0 || ln == varLen {
				ok = false
			}
			t.fields = append(t.fields, field{typ, ln})
			t.recLen += ln
		}
		base.id = id
		switch {
		case n == 0 && base.ipfix:
			c.delete(base)
		case ok && t.recLen > 0 && t.recLen <= maxRecLen: // a zero-length record would never advance
			c.put(base, t)
		default:
			bad++
		}
	}
	return bad
}

// decodeData reads the records of one data set; padding shorter than a record is ignored.
func decodeData(t *template, b []byte) []Flow { return decodeRecords(t, b, nil) }

// decodeRecords is decodeData that hands each flow and its sampling fields to scale.
func decodeRecords(t *template, b []byte, scale func(*Flow, sampling)) []Flow {
	var out []Flow
	if t.recLen <= 0 {
		return nil // defence in depth: the loop below advances by recLen
	}
	for len(b) >= t.recLen {
		rec := b[:t.recLen]
		b = b[t.recLen:]
		var f Flow
		var sp sampling
		addrs := 0
		for _, fd := range t.fields {
			v := rec[:fd.n]
			rec = rec[fd.n:]
			n := uintN(v)
			sp.read(fd.typ, n)
			switch fd.typ {
			case ieBytes:
				f.Bytes = n
			case iePackets:
				f.Packets = n
			case ieProto:
				f.Proto = uint8(n)
			case ieSrcPort:
				f.SrcPort = uint16(n)
			case ieDstPort:
				f.DstPort = uint16(n)
			case ieInIf:
				f.InIf = uint32(n)
			case ieOutIf:
				f.OutIf = uint32(n)
			case ieSrcV4, ieSrcV6:
				if a, ok := addrOf(v); ok {
					f.Src = a
					addrs++
				}
			case ieDstV4, ieDstV6:
				if a, ok := addrOf(v); ok {
					f.Dst = a
					addrs++
				}
			}
		}
		if addrs == 2 {
			if scale != nil {
				scale(&f, sp)
			}
			out = append(out, f)
		}
	}
	return out
}
