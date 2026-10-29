package netflow

const ipfixHeaderLen = 16

// DecodeIPFIX decodes one IPFIX message from exporter (RFC 7011). Variable-length templates are
// not supported and their data sets are counted as missing.
func (c *Templates) DecodeIPFIX(exporter string, b []byte) ([]Flow, int, error) {
	if len(b) < ipfixHeaderLen || be16(b) != 10 {
		return nil, 0, ErrMalformed
	}
	if n := int(be16(b[2:])); n < ipfixHeaderLen || n > len(b) {
		return nil, 0, ErrMalformed
	} else {
		b = b[:n]
	}
	return c.decodeSets(exporter, be32(b[12:]), b[ipfixHeaderLen:], true)
}
