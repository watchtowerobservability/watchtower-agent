package trace

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// HTTPMsg is a parsed HTTP request or response head. Only allowlisted headers are kept.
type HTTPMsg struct {
	Request     bool
	Method      string
	Path        string // no query string, no fragment
	Authority   string
	Status      int
	Traceparent string
	ContentType string
	GRPCStatus  string
	AmzTarget   string // x-amz-target, e.g. DynamoDB_20120810.PutItem
	Stream      uint32 // HTTP/2 stream id, 0 for HTTP/1
	H2          bool
}

var methods = map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true}

// StripQuery cuts the query string and fragment from a request target.
func StripQuery(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		return target[:i]
	}
	return target
}

// keep reports whether a header (lower case) is read at all. Everything else, including
// authorization and cookie, is skipped without being copied.
func keep(name string) bool {
	switch name {
	case "host", ":authority", "traceparent", "content-type", "grpc-status", "x-amz-target":
		return true
	}
	return false
}

func (m *HTTPMsg) set(name, val string) {
	switch name {
	case "host", ":authority":
		m.Authority = val
	case "traceparent":
		m.Traceparent = val
	case "content-type":
		m.ContentType = val
	case "grpc-status":
		m.GRPCStatus = val
	case "x-amz-target":
		m.AmzTarget = val
	}
}

// ParseHTTP1 parses an HTTP/1.x request or response head. ok is false for anything else.
func ParseHTTP1(b []byte) (m HTTPMsg, ok bool) {
	head, _, _ := bytes.Cut(b, []byte("\r\n\r\n")) // a 512 byte capture may stop mid headers
	lines := strings.Split(string(head), "\r\n")
	f := strings.Fields(lines[0])
	switch {
	case len(f) == 3 && methods[f[0]] && strings.HasPrefix(f[2], "HTTP/1."):
		m.Request, m.Method, m.Path = true, f[0], StripQuery(f[1])
	case len(f) >= 2 && strings.HasPrefix(f[0], "HTTP/1."):
		n, err := strconv.Atoi(f[1])
		if err != nil || n < 100 || n > 599 {
			return m, false
		}
		m.Status = n
	default:
		return m, false
	}
	for _, l := range lines[1:] {
		name, val, found := strings.Cut(l, ":")
		if !found {
			continue
		}
		if name = strings.ToLower(name); keep(name) {
			m.set(name, strings.TrimSpace(val))
		}
	}
	return m, true
}

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// H2Conn decodes the HEADERS frames of one HTTP/2 connection direction. A header block cut by the
// 512 B capture, or continued in a frame we do not decode, loses HPACK table updates. From then
// on the direction decodes with an empty zero-size dynamic table: literal and static-indexed fields
// still decode, a reference to a lost dynamic entry errors out (partial message) instead of
// resolving to another request's method or path.
// shortcut: after the first lost block, fields only reachable via the dynamic table are missing
// (e.g. :path re-sent as an index); upgrade by capturing whole frames.
type H2Conn struct {
	dec    *hpack.Decoder
	desync bool
}

// IsH2 reports whether b starts with the HTTP/2 client preface.
func IsH2(b []byte) bool { return bytes.HasPrefix(b, []byte(h2Preface)) }

// Feed decodes the HEADERS frames in b. Messages without a method or status are dropped.
func (c *H2Conn) Feed(b []byte) []HTTPMsg {
	if c.dec == nil {
		c.dec = hpack.NewDecoder(4096, nil)
	}
	b = bytes.TrimPrefix(b, []byte(h2Preface))
	var out []HTTPMsg
	for len(b) >= 9 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		typ, flags := b[3], b[4]
		stream := uint32(b[5]&0x7f)<<24 | uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8])
		b = b[9:]
		pl := b
		if n < len(pl) {
			pl = pl[:n]
		}
		if typ == 1 { // HEADERS
			if m, ok := c.headers(pl, flags, stream); ok {
				out = append(out, m)
			}
		}
		if typ == 9 || (typ == 1 && (n > len(b) || flags&0x4 == 0)) { // CONTINUATION, or cut/unfinished HEADERS
			c.desync = true
		}
		if typ == 1 && n > len(b) {
			return out
		}
		if n >= len(b) {
			break
		}
		b = b[n:]
	}
	return out
}

func (c *H2Conn) headers(pl []byte, flags byte, stream uint32) (HTTPMsg, bool) {
	if flags&0x8 != 0 && len(pl) > 0 { // PADDED
		pad := int(pl[0])
		pl = pl[1:]
		if pad <= len(pl) {
			pl = pl[:len(pl)-pad]
		}
	}
	if flags&0x20 != 0 { // PRIORITY
		if len(pl) < 5 {
			return HTTPMsg{}, false
		}
		pl = pl[5:]
	}
	m := HTTPMsg{H2: true, Stream: stream}
	if c.desync { // fresh each block so a half-parsed earlier block cannot leak into this one
		c.dec = hpack.NewDecoder(0, nil)
	}
	c.dec.SetEmitFunc(func(f hpack.HeaderField) {
		switch f.Name {
		case ":method":
			m.Request, m.Method = true, f.Value
		case ":path":
			m.Path = StripQuery(f.Value)
		case ":status":
			m.Status, _ = strconv.Atoi(f.Value)
		default:
			if keep(f.Name) {
				m.set(f.Name, f.Value)
			}
		}
	})
	_, _ = c.dec.Write(pl) // a truncated block still emitted its leading fields
	return m, m.Request || m.Status != 0 || m.GRPCStatus != ""
}

// IsGRPC reports whether the message belongs to a gRPC call.
func (m HTTPMsg) IsGRPC() bool { return strings.HasPrefix(m.ContentType, "application/grpc") }

// GrpcMethod splits "/pkg.Service/Method".
func GrpcMethod(path string) (service, method string, ok bool) {
	service, method, ok = strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !ok || service == "" || method == "" || strings.Contains(method, "/") {
		return "", "", false
	}
	return service, method, true
}

// Traceparent is a parsed W3C trace context header.
type Traceparent struct {
	TraceID [16]byte
	SpanID  [8]byte
	Flags   byte
}

// ParseTraceparent parses "00-<32 hex>-<16 hex>-<2 hex>" and rejects all-zero ids.
func ParseTraceparent(s string) (tp Traceparent, ok bool) {
	p := strings.Split(strings.TrimSpace(s), "-")
	if len(p) < 4 || len(p[0]) != 2 || len(p[1]) != 32 || len(p[2]) != 16 || len(p[3]) != 2 || p[0] == "ff" {
		return tp, false
	}
	if _, err := hex.Decode(tp.TraceID[:], []byte(p[1])); err != nil {
		return tp, false
	}
	if _, err := hex.Decode(tp.SpanID[:], []byte(p[2])); err != nil {
		return tp, false
	}
	var fl [1]byte
	if _, err := hex.Decode(fl[:], []byte(p[3])); err != nil {
		return tp, false
	}
	tp.Flags = fl[0]
	return tp, tp.TraceID != [16]byte{} && tp.SpanID != [8]byte{}
}
