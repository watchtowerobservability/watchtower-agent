package srcconv

// Minimal MessagePack decoder for the Datadog trace payloads. Hostile input is bounded: nesting is
// capped at mpMaxDepth, a declared length that exceeds the bytes left is rejected before anything is
// allocated (so a 10 MB declared string or array in a 20-byte body costs nothing), and the number of
// decoded values is capped.

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"time"
)

const (
	mpMaxDepth = 32
	// MPMaxValues caps decoded values (and protobuf fields) per payload.
	MPMaxValues = 1 << 20
	mpMaxValues = MPMaxValues
)

var (
	errMsgpack = errors.New("malformed msgpack")
	// ErrMsgpackShort means the input ended inside a value: a stream reader should wait for more bytes.
	ErrMsgpackShort = errors.New("truncated msgpack")
)

// MsgpackDecode decodes one value. Maps become map[string]any (non-string keys are rejected), arrays
// []any, strings string, bin []byte, non-negative ints uint64, negative ints int64, floats float64.
func MsgpackDecode(b []byte) (any, error) {
	d := &mpDec{b: b, budget: mpMaxValues}
	v := d.value(0)
	if d.err != nil {
		return nil, d.err
	}
	return v, nil
}

// MsgpackNext decodes the first value of a stream and returns the bytes after it. With ext, the
// Fluent forward EventTime extension (type 0) decodes to time.Time and other extensions to
// []byte; without it extensions are rejected (the Datadog behaviour).
func MsgpackNext(b []byte, ext bool) (any, []byte, error) {
	d := &mpDec{b: b, budget: mpMaxValues, ext: ext}
	v := d.value(0)
	if d.err != nil {
		return nil, nil, d.err
	}
	return v, d.b, nil
}

type mpDec struct {
	b      []byte
	budget int
	err    error
	ext    bool
}

func (d *mpDec) fail() any {
	if d.err == nil {
		d.err = errMsgpack
	}
	return nil
}

func (d *mpDec) take(n uint64) []byte {
	if d.err != nil {
		return nil
	}
	if n > uint64(len(d.b)) {
		d.err = ErrMsgpackShort
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}

func (d *mpDec) uint(n int) uint64 {
	b := d.take(uint64(n))
	if b == nil {
		return 0
	}
	switch n {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	}
	return binary.BigEndian.Uint64(b)
}

func (d *mpDec) value(depth int) any {
	if d.budget--; d.budget < 0 || depth > mpMaxDepth || d.err != nil {
		return d.fail()
	}
	t := d.take(1)
	if t == nil {
		return nil
	}
	c := t[0]
	switch {
	case c <= 0x7f:
		return uint64(c)
	case c >= 0xe0:
		return int64(int8(c)) //nolint:gosec // negative fixint
	case c >= 0xa0 && c <= 0xbf:
		return d.str(uint64(c & 0x1f))
	case c >= 0x90 && c <= 0x9f:
		return d.array(uint64(c&0x0f), depth)
	case c >= 0x80 && c <= 0x8f:
		return d.mapv(uint64(c&0x0f), depth)
	}
	switch c {
	case 0xc0:
		return nil
	case 0xc2:
		return false
	case 0xc3:
		return true
	case 0xc4, 0xc5, 0xc6: // bin 8/16/32
		return append([]byte(nil), d.take(d.uint(1<<(c-0xc4)))...)
	case 0xca:
		return float64(math.Float32frombits(uint32(d.uint(4)))) //nolint:gosec // 32 bits
	case 0xcb:
		return math.Float64frombits(d.uint(8))
	case 0xcc, 0xcd, 0xce, 0xcf:
		return d.uint(1 << (c - 0xcc))
	case 0xd0:
		return int64(int8(d.uint(1))) //nolint:gosec // sign extension
	case 0xd1:
		return int64(int16(d.uint(2))) //nolint:gosec // sign extension
	case 0xd2:
		return int64(int32(d.uint(4))) //nolint:gosec // sign extension
	case 0xd3:
		return int64(d.uint(8)) //nolint:gosec // sign extension
	case 0xd9, 0xda, 0xdb:
		return d.str(d.uint(1 << (c - 0xd9)))
	case 0xdc:
		return d.array(d.uint(2), depth)
	case 0xdd:
		return d.array(d.uint(4), depth)
	case 0xde:
		return d.mapv(d.uint(2), depth)
	case 0xdf:
		return d.mapv(d.uint(4), depth)
	}
	if d.ext && ((c >= 0xd4 && c <= 0xd8) || (c >= 0xc7 && c <= 0xc9)) {
		return d.extension(c)
	}
	return d.fail() // ext types and 0xc1 are not used by the Datadog agent
}

// extension reads an ext value whose header byte is c (fixext 0xd4-0xd8, ext 8/16/32 0xc7-0xc9).
func (d *mpDec) extension(c byte) any {
	var n uint64
	switch c {
	case 0xc7, 0xc8, 0xc9:
		n = d.uint(1 << (c - 0xc7))
	default:
		n = 1 << (c - 0xd4)
	}
	t := d.take(1)
	body := d.take(n)
	if d.err != nil || len(t) == 0 {
		return nil
	}
	if int8(t[0]) == 0 && len(body) == 8 { //nolint:gosec // ext type id
		return time.Unix(int64(binary.BigEndian.Uint32(body)), int64(binary.BigEndian.Uint32(body[4:]))).UTC()
	}
	return append([]byte(nil), body...)
}

func (d *mpDec) str(n uint64) any {
	b := d.take(n)
	if d.err != nil {
		return nil
	}
	return string(b)
}

func (d *mpDec) array(n uint64, depth int) any {
	if n > uint64(len(d.b)) { // every element is at least one byte
		d.err = ErrMsgpackShort
		return nil
	}
	out := make([]any, 0, n)
	for i := uint64(0); i < n && d.err == nil; i++ {
		out = append(out, d.value(depth+1))
	}
	return out
}

func (d *mpDec) mapv(n uint64, depth int) any {
	if n > uint64(len(d.b))/2 {
		d.err = ErrMsgpackShort
		return nil
	}
	out := make(map[string]any, n)
	for i := uint64(0); i < n && d.err == nil; i++ {
		var k string
		switch kv := d.value(depth + 1).(type) {
		case string:
			k = kv
		case uint64: // v0.5 traces key meta by string-table index
			k = strconv.FormatUint(kv, 10)
		default:
			return d.fail()
		}
		out[k] = d.value(depth + 1)
	}
	return out
}
