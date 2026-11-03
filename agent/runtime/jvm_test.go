package runtime

import (
	"encoding/binary"
	"testing"
	"time"
)

func entry(name string, typ byte, val []byte, vlen int) []byte {
	nameOff := 20
	doff := nameOff + len(name) + 1
	for doff%8 != 0 {
		doff++
	}
	e := make([]byte, doff+len(val))
	binary.LittleEndian.PutUint32(e[0:], uint32(len(e)))
	binary.LittleEndian.PutUint32(e[4:], uint32(nameOff))
	binary.LittleEndian.PutUint32(e[8:], uint32(vlen))
	e[12] = typ
	binary.LittleEndian.PutUint32(e[16:], uint32(doff))
	copy(e[nameOff:], name)
	copy(e[doff:], val)
	return e
}

func long(v int64) []byte { return binary.LittleEndian.AppendUint64(nil, uint64(v)) }

type rec struct{ names []string }

func (r *rec) Gauge(n, _ string, _ float64, _ map[string]string, _ time.Time) {
	r.names = append(r.names, n)
}
func (r *rec) Sum(n, _ string, _ float64, _ map[string]string, _ time.Time) {
	r.names = append(r.names, n)
}

func TestParsePerfData(t *testing.T) {
	var body []byte
	es := [][]byte{entry("java.threads.live", 'J', long(17), 0), entry("sun.gc.collector.0.invocations", 'J', long(3), 0),
		entry("sun.gc.collector.0.name", 'B', []byte("G1 Young\x00"), 9), entry("sun.gc.generation.0.space.0.used", 'J', long(1<<20), 0)}
	for _, e := range es {
		body = append(body, e...)
	}
	h := make([]byte, 32)
	binary.BigEndian.PutUint32(h, perfMagic)
	h[4], h[5] = 1, 2 // little endian, v2
	binary.LittleEndian.PutUint32(h[24:], 32)
	binary.LittleEndian.PutUint32(h[28:], uint32(len(es)))
	pd, err := ParsePerfData(append(h, body...))
	if err != nil || pd.Longs["java.threads.live"] != 17 || pd.Strings["sun.gc.collector.0.name"] != "G1 Young" {
		t.Fatalf("%+v %v", pd, err)
	}
	r := &rec{}
	Emit(r, pd, nil, time.Now())
	if len(r.names) < 5 {
		t.Fatalf("emitted %v", r.names)
	}
}
