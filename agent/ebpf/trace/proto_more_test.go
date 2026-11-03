package trace

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func ucs2(s string) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, c)
	}
	return out
}

func TestParseTDSRPCExecuteSQL(t *testing.T) {
	stmt := ucs2("SELECT 1 FROM t")
	b := []byte{0x03, 1, 0, 0, 0, 0, 1, 0}
	b = append(b, 4, 0, 0, 0)              // ALL_HEADERS length
	b = append(b, 0xFF, 0xFF, 10, 0, 0, 0) // sp_executesql, flags
	b = append(b, 0, 0, 0xE7)              // no name, status, NVARCHAR
	b = binary.LittleEndian.AppendUint16(b, 8000)
	b = append(b, 0, 0, 0, 0, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(stmt))) //nolint:gosec // test
	b = append(b, stmt...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b))) //nolint:gosec // test
	m, ok := ParseTDSRPC(b)
	if !ok || m.Dest != "sp_executesql" || m.Stmt != "SELECT 1 FROM t" {
		t.Fatalf("%+v %v", m, ok)
	}
}

func TestParseDNSTCP(t *testing.T) {
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'w', 't', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	b := append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...) //nolint:gosec // test
	if m, ok := ParseDNSTCP(b); !ok || m.Dest != "wt.com" {
		t.Fatalf("%+v %v", m, ok)
	}
	if _, ok := ParseDNSTCP(b[:len(b)-1]); ok {
		t.Fatal("a wrong length must not be claimed")
	}
}

func TestParsersRefuseOtherTraffic(t *testing.T) {
	heads := [][]byte{[]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n padding padding padding padding"), make([]byte, 64), {0x80}}
	for _, h := range heads {
		for name, p := range map[string]func([]byte) (Msg, bool){"tds": ParseTDSRPC, "aero": ParseAerospike, "rpc": ParseSunRPC, "amqp": ParseAMQP1, "dns": ParseDNSTCP} {
			if _, ok := p(h); ok {
				t.Errorf("%s claimed %q", name, h)
			}
		}
	}
	if _, ok := ParseCouchbase(append([]byte{0x80, 0x00}, make([]byte, 22)...)); !ok {
		t.Error("a binary get must be claimed")
	}
}

func TestClassifyN1QLAndVector(t *testing.T) {
	p := &pending{}
	p.Attrs = map[string]any{}
	classifyRequest(p, HTTPMsg{Path: "/query/service", Authority: "cb:8093"}, []byte(`{"statement":"SELECT * FROM b"}`))
	if p.Attrs["db.system.name"] != "couchbase" || p.Attrs["db.query.text"] != "SELECT * FROM b" {
		t.Fatalf("%v", p.Attrs)
	}
	p = &pending{}
	p.Attrs = map[string]any{}
	classifyRequest(p, HTTPMsg{Path: "/collections/docs/points/search", Authority: "qdrant:6333"}, nil)
	if p.Attrs["db.system.name"] != "qdrant" {
		t.Fatalf("%v", p.Attrs)
	}
}
