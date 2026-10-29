package snmp

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// A tiny SNMPv2c agent: BER-encodes GetResponse packets by hand so the polling code can be
// exercised over a real UDP socket without a device.

type vb struct {
	oid string
	tag byte
	val []byte
}

type fakeAgent struct {
	mu   sync.Mutex
	vars []vb
}

func tlv(tag byte, b []byte) []byte {
	n := len(b)
	var l []byte
	switch {
	case n < 128:
		l = []byte{byte(n)}
	case n < 256:
		l = []byte{0x81, byte(n)}
	default:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), b...)
}

// rd reads one TLV: tag, value and what follows.
func rd(b []byte) (byte, []byte, []byte) {
	tag, n, off := b[0], int(b[1]), 2
	if b[1] >= 0x80 {
		k := int(b[1] & 0x7f)
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		off = 2 + k
	}
	return tag, b[off : off+n], b[off+n:]
}

func encOID(s string) []byte {
	var p []int
	for _, f := range strings.Split(strings.TrimPrefix(s, "."), ".") {
		n, _ := strconv.Atoi(f)
		p = append(p, n)
	}
	out := []byte{byte(p[0]*40 + p[1])}
	for _, n := range p[2:] {
		var t []byte
		t = append(t, byte(n&0x7f))
		for n >>= 7; n > 0; n >>= 7 {
			t = append(t, byte(n&0x7f|0x80))
		}
		for i := len(t) - 1; i >= 0; i-- {
			out = append(out, t[i])
		}
	}
	return out
}

func decOID(b []byte) string {
	s := []string{strconv.Itoa(int(b[0]) / 40), strconv.Itoa(int(b[0]) % 40)}
	n := 0
	for _, c := range b[1:] {
		n = n<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			s = append(s, strconv.Itoa(n))
			n = 0
		}
	}
	return strings.Join(s, ".")
}

func cmpOID(a, b string) int {
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		p, _ := strconv.Atoi(x[i])
		q, _ := strconv.Atoi(y[i])
		if p != q {
			return p - q
		}
	}
	return len(x) - len(y)
}

func uintBytes(v uint64) []byte {
	var b []byte
	for ; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

func vInt(oid string, v uint64) vb       { return vb{oid, 0x02, uintBytes(v)} }
func vCounter32(oid string, v uint64) vb { return vb{oid, 0x41, uintBytes(v)} }
func vGauge(oid string, v uint64) vb     { return vb{oid, 0x42, uintBytes(v)} }
func vStr(oid, s string) vb              { return vb{oid, 0x04, []byte(s)} }
func vTicks(oid string, v uint64) vb     { return vb{oid, 0x43, uintBytes(v)} }

func (f *fakeAgent) set(v vb) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.vars {
		if f.vars[i].oid == v.oid {
			f.vars[i] = v
			return
		}
	}
	f.vars = append(f.vars, v)
	sort.Slice(f.vars, func(i, j int) bool { return cmpOID(f.vars[i].oid, f.vars[j].oid) < 0 })
}

func (f *fakeAgent) next(oid string, n int) []vb {
	var out []vb
	for _, v := range f.vars {
		if cmpOID(v.oid, oid) > 0 && len(out) < n {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		out = append(out, vb{oid, 0x82, nil}) // endOfMibView
	}
	return out
}

func (f *fakeAgent) respond(pkt []byte) []byte {
	_, msg, _ := rd(pkt)
	_, ver, r := rd(msg)
	_, comm, r := rd(r)
	if string(comm) != "public" {
		return nil
	}
	ptag, pdu, _ := rd(r)
	_, reqid, r := rd(pdu)
	_, _, r = rd(r)
	_, maxrep, r := rd(r)
	_, list, _ := rd(r)
	max := 0
	for _, c := range maxrep {
		max = max<<8 | int(c)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []vb
	for len(list) > 0 {
		var one []byte
		_, one, list = rd(list)
		_, o, _ := rd(one)
		oid := decOID(o)
		switch ptag {
		case 0xa5:
			out = append(out, f.next(oid, max)...)
		case 0xa1:
			out = append(out, f.next(oid, 1)...)
		default:
			found := vb{oid, 0x81, nil} // noSuchInstance
			for _, v := range f.vars {
				if v.oid == oid {
					found = v
				}
			}
			out = append(out, found)
		}
	}
	var vbs []byte
	for _, v := range out {
		vbs = append(vbs, tlv(0x30, append(tlv(0x06, encOID(v.oid)), tlv(v.tag, v.val)...))...)
	}
	body := append(append(tlv(0x02, reqid), tlv(0x02, []byte{0})...), tlv(0x02, []byte{0})...)
	body = append(body, tlv(0x30, vbs)...)
	m := append(append(tlv(0x02, ver), tlv(0x04, comm)...), tlv(0xa2, body)...)
	return tlv(0x30, m)
}

// startFake listens on a loopback UDP port and returns the agent and its address.
func startFake(t *testing.T) (*fakeAgent, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f := &fakeAgent{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := f.respond(buf[:n]); resp != nil {
				_, _ = conn.WriteToUDP(resp, from)
			}
		}
	}()
	return f, conn.LocalAddr().String()
}
