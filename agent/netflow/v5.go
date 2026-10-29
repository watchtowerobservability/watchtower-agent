package netflow

import "net/netip"

const (
	v5HeaderLen = 24
	v5RecordLen = 48
	v5MaxCount  = 30
)

// DecodeV5 decodes a NetFlow v5 datagram. The sampling interval of the header scales the counters.
func DecodeV5(b []byte) ([]Flow, error) {
	if len(b) < v5HeaderLen || be16(b) != 5 {
		return nil, ErrMalformed
	}
	n := int(be16(b[2:]))
	if n == 0 || n > v5MaxCount || len(b) != v5HeaderLen+n*v5RecordLen {
		return nil, ErrMalformed
	}
	scale := uint64(be16(b[22:]) & 0x3fff)
	if scale == 0 {
		scale = 1
	}
	out := make([]Flow, 0, n)
	for i := range n {
		r := b[v5HeaderLen+i*v5RecordLen:]
		out = append(out, Flow{
			Src:     netip.AddrFrom4([4]byte(r[0:4])),
			Dst:     netip.AddrFrom4([4]byte(r[4:8])),
			InIf:    uint32(be16(r[12:])),
			OutIf:   uint32(be16(r[14:])),
			Packets: uint64(be32(r[16:])) * scale,
			Bytes:   uint64(be32(r[20:])) * scale,
			SrcPort: be16(r[32:]),
			DstPort: be16(r[34:]),
			Proto:   r[38],
		})
	}
	return out, nil
}
