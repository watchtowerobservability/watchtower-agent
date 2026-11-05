package trace

import (
	"bytes"
	"container/list"
	"maps"
	"strconv"
	"strings"
	"time"
)

// Dir is the direction of a captured socket or TLS call, from the observed process.
type Dir uint8

// Directions.
const (
	Send Dir = iota // write, send, SSL_write: a request on a client, a response on a server
	Recv
)

// Event is the head (up to 512 bytes) of one read or write.
type Event struct {
	TS        time.Time
	PID       uint32
	FD        int32 // socket fd, or the TLS connection pointer for uprobes
	Dir       Dir
	TLS       bool
	Data      []byte
	PeerAddr  string
	PeerPort  int64
	LocalPort int64 // the socket's local port; server.port on a SERVER span
}

type connKey struct {
	pid uint32
	fd  int32
}

type pending struct {
	Span
	proto string
	dir   Dir   // direction of the request event
	corr  int32 // request id the response must echo (kafka, mongodb)
}

type conn struct {
	h2   [2]H2Conn // per direction, HPACK tables are per direction
	reqs map[uint32]*pending
}

// connNode is a connection and its key, carried by an element of the LRU list.
type connNode struct {
	key connKey
	c   *conn
}

// Assembler pairs request and response heads into spans. It is not safe for concurrent use.
type Assembler struct {
	conns map[connKey]*list.Element // key -> element holding *connNode
	order *list.List                // front = most recently used
	// Bodies keeps the HTTP/1 request and response heads on the span for payload capture.
	Bodies bool
}

// NewAssembler returns an empty assembler.
func NewAssembler() *Assembler {
	return &Assembler{conns: map[connKey]*list.Element{}, order: list.New()}
}

const maxConns = 4096

// Forget drops a connection's state (called when the socket closes).
func (a *Assembler) Forget(pid uint32, fd int32) {
	k := connKey{pid, fd}
	if el, ok := a.conns[k]; ok {
		a.order.Remove(el)
		delete(a.conns, k)
	}
}

// Handle consumes one event and returns the span it completes, if any.
func (a *Assembler) Handle(ev Event) (Span, bool) {
	k := connKey{ev.PID, ev.FD}
	var c *conn
	if el, ok := a.conns[k]; ok {
		a.order.MoveToFront(el)
		c = el.Value.(*connNode).c
	} else {
		if len(a.conns) >= maxConns {
			// Evict the least-recently-used connection; a flood only loses the stalest pairing
			// state instead of every connection's.
			if back := a.order.Back(); back != nil {
				a.order.Remove(back)
				delete(a.conns, back.Value.(*connNode).key)
			}
		}
		c = &conn{reqs: map[uint32]*pending{}}
		a.conns[k] = a.order.PushFront(&connNode{key: k, c: c})
	}
	var h2 []HTTPMsg // decoded once: HPACK state must see each block exactly once
	if IsH2(ev.Data) || c.h2[ev.Dir].dec != nil || looksLikeFrames(ev.Data) {
		h2 = c.h2[ev.Dir].Feed(ev.Data)
		if h2 == nil {
			return Span{}, false
		}
	}
	if sp, ok := a.response(c, ev, h2); ok {
		return sp, true
	}
	return a.request(c, ev, h2)
}

func (a *Assembler) response(c *conn, ev Event, h2 []HTTPMsg) (Span, bool) {
	if len(c.reqs) == 0 {
		return Span{}, false
	}
	for _, m := range h2 {
		if p := c.reqs[m.Stream]; p != nil && !m.Request && p.dir != ev.Dir {
			delete(c.reqs, m.Stream)
			return finishHTTP(p, m, ev.TS), true
		}
	}
	p := c.reqs[0]
	if p == nil || p.dir == ev.Dir {
		return Span{}, false
	}
	switch p.proto {
	case "http":
		if m, ok := ParseHTTP1(ev.Data); ok && !m.Request {
			delete(c.reqs, 0)
			classifyResponse(p, ev.Data)
			if a.Bodies {
				p.resHead = bytes.Clone(ev.Data)
			}
			return finishHTTP(p, m, ev.TS), true
		}
	case "postgresql":
		if ok, isErr := IsPostgresResponse(ev.Data); ok {
			return finishDB(c, p, isErr, ev.TS), true
		}
	case "mysql":
		if ok, isErr := IsMySQLResponse(ev.Data); ok {
			return finishDB(c, p, isErr, ev.TS), true
		}
	case "redis":
		if ok, isErr := IsRedisResponse(ev.Data); ok {
			return finishDB(c, p, isErr, ev.TS), true
		}
	default:
		if ok, isErr := otherResponse(p, ev.Data); ok {
			return finishDB(c, p, isErr, ev.TS), true
		}
	}
	return Span{}, false
}

func finishDB(c *conn, p *pending, isErr bool, end time.Time) Span {
	delete(c.reqs, 0)
	p.End, p.Error = end, isErr
	return p.Span
}

// looksLikeFrames is a cheap check for a HEADERS frame so plain protocols are not fed to HPACK.
func looksLikeFrames(b []byte) bool {
	return len(b) >= 9 && b[3] == 1 && b[5]&0x80 == 0 && (int(b[0])<<16|int(b[1])<<8|int(b[2])) <= 1<<14
}

// request starts a span; fire-and-forget messages come back finished at once.
func (a *Assembler) request(c *conn, ev Event, h2 []HTTPMsg) (Span, bool) {
	base := Span{Client: ev.Dir == Send, Start: ev.TS, PID: ev.PID, Attrs: map[string]any{}}
	newID(base.TraceID[:])
	newID(base.SpanID[:])
	peer := "server"
	if !base.Client {
		peer = "client"
	}
	if ev.PeerAddr != "" {
		base.Attrs[peer+".address"] = ev.PeerAddr
		base.Attrs[peer+".port"] = ev.PeerPort
	}
	if !base.Client && ev.LocalPort > 0 { // the listening port a request arrived on
		base.Attrs["server.port"] = ev.LocalPort
	}
	p := &pending{Span: base, dir: ev.Dir}
	if h2 != nil {
		for _, m := range h2 {
			if m.Request {
				q := *p
				q.Attrs = maps.Clone(p.Attrs)
				newID(q.TraceID[:])
				newID(q.SpanID[:])
				applyHTTP(&q, m)
				c.reqs[m.Stream] = &q
			}
		}
		return Span{}, false
	}
	if m, ok := ParseHTTP1(ev.Data); ok && m.Request {
		applyHTTP(p, m)
		classifyRequest(p, m, bodyOf(ev.Data))
		if a.Bodies {
			p.reqHead = bytes.Clone(ev.Data)
		}
		c.reqs[0] = p
	} else if q, ok := ParsePostgres(ev.Data); ok {
		setDB(p, "postgresql", q, true, c)
	} else if m, ok := strictBinary(ev.Data); ok { // before MySQL, whose header check is loose
		applyMsg(p, m, c)
		c.reqs[0] = p
	} else if q, ok := ParseMySQL(ev.Data); ok {
		setDB(p, "mysql", q, false, c)
	} else if cmd, ok := ParseRedis(ev.Data); ok {
		p.proto = "redis"
		p.Name = cmd
		p.Attrs["db.system"] = "redis"
		p.Attrs["db.query.text"] = cmd // the verb only; arguments are never read
		p.Attrs["db.operation.name"] = cmd
		c.reqs[0] = p
	} else {
		for _, parse := range otherParsers {
			m, ok := parse(ev.Data)
			if !ok {
				continue
			}
			applyMsg(p, m, c)
			if m.Immediate {
				p.End = ev.TS
				// a deliver/receive seen on the consumer is a span of the consumer itself
				return p.Span, true
			}
			c.reqs[0] = p
			break
		}
	}
	return Span{}, false
}

func setDB(p *pending, system, stmt string, pg bool, c *conn) {
	norm := NormalizeSQL(stmt, pg)
	p.proto = system
	op, _, _ := strings.Cut(norm, " ")
	p.Name = strings.ToUpper(op)
	p.Attrs["db.system"] = system
	p.Attrs["db.query.text"] = norm
	p.Attrs["db.operation.name"] = p.Name
	c.reqs[0] = p
}

func applyHTTP(p *pending, m HTTPMsg) {
	p.proto = "http"
	p.Name = m.Method
	p.Attrs["http.request.method"] = m.Method
	p.Attrs["url.path"] = m.Path
	if m.Authority != "" && p.Client {
		p.Attrs["server.address"] = strings.Split(m.Authority, ":")[0]
	}
	if m.IsGRPC() {
		p.Attrs["rpc.system"] = "grpc"
		if svc, meth, ok := GrpcMethod(m.Path); ok {
			p.Attrs["rpc.service"], p.Attrs["rpc.method"] = svc, meth
			p.Name = svc + "/" + meth
		}
	}
	if tp, ok := ParseTraceparent(m.Traceparent); ok {
		p.TraceID, p.ParentID, p.HasParent = tp.TraceID, tp.SpanID, true
	}
}

func finishHTTP(p *pending, m HTTPMsg, end time.Time) Span {
	p.End = end
	if m.Status != 0 {
		p.Attrs["http.response.status_code"] = int64(m.Status)
		p.Error = m.Status >= 500 || (p.Client && m.Status >= 400)
	}
	if m.GRPCStatus != "" {
		p.Attrs["rpc.grpc.status_code"], _ = strconv.ParseInt(m.GRPCStatus, 10, 64)
		p.Error = p.Error || m.GRPCStatus != "0"
	}
	return p.Span
}
