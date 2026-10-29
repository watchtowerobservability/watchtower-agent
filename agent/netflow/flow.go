// Package netflow is the agent's flow collector: NetFlow v5/v9, IPFIX and sFlow v5 over UDP,
// reduced to the top conversations per exporter and minute and sent as OTLP log records
// (`event.name = network.flow`). Every decoder treats its input as hostile: lengths are checked
// before any read, caches are bounded, and a bad packet is counted and dropped.
package netflow

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Flow is one decoded flow record.
type Flow struct {
	Exporter         string
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	InIf, OutIf      uint32
	Bytes, Packets   uint64
}

// ErrMalformed is returned for a packet that is truncated or inconsistent.
var ErrMalformed = errors.New("netflow: malformed packet")

// uintN reads a big-endian unsigned integer of 1 to 8 bytes.
func uintN(b []byte) uint64 {
	if len(b) == 0 || len(b) > 8 {
		return 0
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// addrOf reads a 4 or 16 byte address.
func addrOf(b []byte) (netip.Addr, bool) {
	if len(b) != 4 && len(b) != 16 {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(b)
	return a.Unmap(), ok
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
