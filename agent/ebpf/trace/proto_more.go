package trace

// Userspace parsers of request heads (CFT-E04, E05): SQL Server RPC, Couchbase, Aerospike, ONC RPC,
// AMQP 1.0 transfers and DNS over TCP. Each checks its header tightly, since these run on any
// head nothing else claimed. All are length-checked; a truncated head is simply not claimed.

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

func init() {
	otherParsers = append(otherParsers, ParseTDSRPC, ParseCouchbase, ParseAerospike, ParseSunRPC, ParseAMQP1, ParseDNSTCP)
}

func utf16le(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b) && len(u) < maxStmt; i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}

// tdsProcs names the well-known stored procedure ids of an RPC request.
var tdsProcs = map[uint16]string{1: "sp_cursor", 2: "sp_cursoropen", 3: "sp_cursorprepare", 4: "sp_cursorexecute", 9: "sp_cursorclose",
	10: "sp_executesql", 11: "sp_prepare", 12: "sp_execute", 13: "sp_prepexec", 14: "sp_prepexecrpc", 15: "sp_unprepare"}

// ParseTDSRPC reads an RPC request packet (type 0x03): the procedure and, for sp_executesql and
// sp_prepexec, the statement text in the first NVARCHAR parameter, the usual path of ORMs.
func ParseTDSRPC(b []byte) (Msg, bool) {
	if len(b) < 16 || b[0] != 0x03 || be16(b[2:]) < 8 {
		return Msg{}, false
	}
	body := b[8:]
	if h := int(binary.LittleEndian.Uint32(body)); h >= 4 && h < len(body) && h <= 1024 {
		body = body[h:]
	}
	if len(body) < 4 {
		return Msg{}, false
	}
	var proc string
	var i int
	if n := binary.LittleEndian.Uint16(body); n == 0xFFFF {
		var ok bool
		if proc, ok = tdsProcs[binary.LittleEndian.Uint16(body[2:])]; !ok {
			return Msg{}, false
		}
		i = 4
	} else {
		i = 2 + int(n)*2
		if n == 0 || n > 256 || i > len(body) {
			return Msg{}, false
		}
		proc = utf16le(body[2:i])
	}
	m := Msg{System: "mssql", Op: "EXEC", Dest: proc}
	if i += 2; proc == "sp_executesql" || proc == "sp_prepexec" { // skip the option flags
		if s, ok := tdsFirstText(body, i); ok {
			m.Stmt = s
		}
	}
	return m, true
}

// tdsFirstText reads a leading NVARCHAR parameter: name, status, type 0xE7, max length, collation, value.
func tdsFirstText(b []byte, i int) (string, bool) {
	if i >= len(b) {
		return "", false
	}
	i += 1 + int(b[i])*2 + 1 // name length, name, status
	if i+8 > len(b) || b[i] != 0xE7 {
		return "", false
	}
	maxLen := binary.LittleEndian.Uint16(b[i+1:])
	i += 8                // type, max length, 5 byte collation
	if maxLen == 0xFFFF { // PLP: 8 byte total length, then 4 byte chunk length
		if i += 12; i > len(b) {
			return "", false
		}
	} else if i += 2; i > len(b) {
		return "", false
	}
	s := utf16le(b[i:])
	return s, len(s) >= 4
}

var couchbaseOps = map[byte]string{0x00: "get", 0x01: "set", 0x02: "add", 0x03: "replace", 0x04: "delete", 0x05: "incr", 0x06: "decr", 0x1d: "get_and_lock"}

// ParseCouchbase reads a memcached binary protocol request, which Couchbase's KV service speaks.
func ParseCouchbase(b []byte) (Msg, bool) {
	if len(b) < 24 || b[0] != 0x80 {
		return Msg{}, false
	}
	op, ok := couchbaseOps[b[1]]
	if !ok {
		return Msg{}, false
	}
	key, extras, total := be16(b[2:]), int(b[4]), int(binary.BigEndian.Uint32(b[8:])) //nolint:gosec // wire size
	if key+extras > total {
		return Msg{}, false
	}
	return Msg{System: "couchbase", Op: op}, true
}

// ParseAerospike reads a message request: version 2, type 3, then a 22 byte header.
func ParseAerospike(b []byte) (Msg, bool) {
	if len(b) < 35 || b[0] != 2 || b[1] != 3 || b[8] != 22 {
		return Msg{}, false
	}
	op := "read"
	if b[10]&1 != 0 {
		op = "write"
	}
	m := Msg{System: "aerospike", Op: op}
	if n := int(binary.BigEndian.Uint32(b[30:])); b[34] == 0 && n > 1 && 35+n-1 <= len(b) { //nolint:gosec // wire size
		m.Dest = string(b[35 : 35+n-1])
	}
	return m, true
}

// ParseSunRPC reads an ONC RPC call over TCP (record marker, xid, CALL, RPC version 2).
func ParseSunRPC(b []byte) (Msg, bool) {
	if len(b) < 28 || b[0]&0x80 == 0 {
		return Msg{}, false
	}
	u := func(i int) uint32 { return binary.BigEndian.Uint32(b[i:]) }
	if u(8) != 0 || u(12) != 2 {
		return Msg{}, false
	}
	return Msg{System: "onc_rpc", Op: strconv.FormatUint(uint64(u(24)), 10), Dest: strconv.FormatUint(uint64(u(16)), 10)}, true
}

// ParseAMQP1 reads an AMQP 1.0 transfer frame (descriptor 0x53 0x14), with or without the protocol header.
func ParseAMQP1(b []byte) (Msg, bool) {
	if bytes.HasPrefix(b, []byte("AMQP\x00\x01\x00\x00")) {
		b = b[8:]
	}
	if len(b) < 11 || b[4] < 2 || b[5] != 0 {
		return Msg{}, false
	}
	off := int(b[4]) * 4
	if off+3 > len(b) || b[off] != 0 || b[off+1] != 0x53 || b[off+2] != 0x14 {
		return Msg{}, false
	}
	return Msg{System: "amqp", Op: "publish", Messaging: true, Immediate: true}, true
}

// ParseDNSTCP reads one standard query over TCP: exactly one length-prefixed question.
func ParseDNSTCP(b []byte) (Msg, bool) {
	if len(b) < 19 || be16(b) != len(b)-2 || b[4]&0xF8 != 0 || be16(b[6:]) != 1 || be16(b[8:]) != 0 {
		return Msg{}, false
	}
	var labels []string
	i := 14
	for {
		if i >= len(b) {
			return Msg{}, false
		}
		n := int(b[i])
		if n == 0 {
			break
		}
		if n > 63 || i+1+n > len(b) {
			return Msg{}, false
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	if len(labels) == 0 {
		return Msg{}, false
	}
	return Msg{System: "dns", Op: "query", Dest: strings.Join(labels, ".")}, true
}
