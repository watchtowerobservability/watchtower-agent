package trace

// More wire protocols (CFT-E04/E05): Kafka produce/fetch, MongoDB OP_MSG, Memcached text, MQTT,
// NATS, AMQP 0-9-1 and SQL Server TDS. Like the SQL parsers, only operation names and
// destinations (topic, collection, subject, exchange) are read; payloads, keys and values never.
// Fire-and-forget messages (MQTT/NATS/AMQP publish and deliver) become zero-length spans at once.

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// Msg is what a protocol parser found in one request head.
type Msg struct {
	System, Op, Dest string
	Corr             int32 // Kafka correlation id / Mongo request id, matched by the response
	Immediate        bool  // no response to wait for
	Messaging        bool  // messaging.* rather than db.* attributes
	Stmt             string
}

func be16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

// kafkaString reads an int16-length string at b[i:]; -1 is null.
func kafkaString(b []byte, i int) (string, int, bool) {
	if i+2 > len(b) {
		return "", i, false
	}
	n := int(int16(binary.BigEndian.Uint16(b[i:]))) //nolint:gosec // wire int16
	i += 2
	if n < 0 {
		return "", i, true
	}
	if i+n > len(b) {
		return "", i, false
	}
	return string(b[i : i+n]), i + n, true
}

// ParseKafka reads a Produce (0) or Fetch (1) request header and, for non-flexible versions,
// the first topic.
func ParseKafka(b []byte) (Msg, bool) {
	if len(b) < 14 {
		return Msg{}, false
	}
	size := int32(binary.BigEndian.Uint32(b))          //nolint:gosec // wire int32
	key, ver := int16(be16(b[4:])), int16(be16(b[6:])) //nolint:gosec // wire int16
	if size < 10 || size > 100<<20 || (key != 0 && key != 1) || ver < 0 || ver > 17 {
		return Msg{}, false
	}
	m := Msg{System: "kafka", Messaging: true, Corr: int32(binary.BigEndian.Uint32(b[8:]))} //nolint:gosec // wire int32
	_, i, ok := kafkaString(b, 12)                                                          // client_id
	if !ok {
		return Msg{}, false
	}
	if key == 0 {
		m.Op = "publish"
		if ver >= 9 { // flexible versions: tagged fields and compact strings, topic not read
			return m, true
		}
		if ver >= 3 {
			if _, i, ok = kafkaString(b, i); !ok { // transactional_id
				return m, true
			}
		}
		i += 2 + 4 // acks, timeout
	} else {
		m.Op = "receive"
		if ver >= 12 {
			return m, true
		}
		i += 4 + 4 + 4 // replica_id, max_wait_ms, min_bytes
		if ver >= 3 {
			i += 4
		}
		if ver >= 4 {
			i++
		}
		if ver >= 7 {
			i += 8
		}
	}
	if i+4 <= len(b) && binary.BigEndian.Uint32(b[i:]) > 0 {
		if t, _, ok := kafkaString(b, i+4); ok {
			m.Dest = t
		}
	}
	return m, true
}

// IsKafkaResponse matches a response header carrying the request's correlation id.
func IsKafkaResponse(b []byte, corr int32) bool {
	return len(b) >= 8 && int32(binary.BigEndian.Uint32(b[4:])) == corr //nolint:gosec // wire int32
}

const mongoOpMsg = 2013

// ParseMongo reads an OP_MSG command: the first BSON key is the command, a string value the
// collection.
func ParseMongo(b []byte) (Msg, bool) {
	if len(b) < 27 || binary.LittleEndian.Uint32(b[12:]) != mongoOpMsg || b[20] != 0 {
		return Msg{}, false
	}
	n := binary.LittleEndian.Uint32(b)
	if n < 21 || n > 48<<20 {
		return Msg{}, false
	}
	doc := b[21+4:] // section kind 0, then the document (int32 length first)
	typ := doc[0]
	key, rest, ok := bytes.Cut(doc[1:], []byte{0})
	if !ok || len(key) == 0 || key[0] == '$' {
		return Msg{}, false
	}
	m := Msg{System: "mongodb", Op: string(key), Corr: int32(binary.LittleEndian.Uint32(b[4:]))} //nolint:gosec // wire int32
	if typ == 0x02 && len(rest) > 4 {
		if l := int(binary.LittleEndian.Uint32(rest)); l > 1 && 4+l <= len(rest) {
			m.Dest = string(rest[4 : 4+l-1])
		}
	}
	return m, true
}

// IsMongoResponse matches the reply to request id corr; an `errmsg` field marks an error.
func IsMongoResponse(b []byte, corr int32) (ok, isErr bool) {
	if len(b) < 16 || binary.LittleEndian.Uint32(b[12:]) != mongoOpMsg || int32(binary.LittleEndian.Uint32(b[8:])) != corr { //nolint:gosec // wire int32
		return false, false
	}
	return true, bytes.Contains(b, []byte("errmsg\x00"))
}

var memcachedVerbs = map[string]bool{"get": true, "gets": true, "gat": true, "gats": true, "set": true, "add": true, "replace": true,
	"append": true, "prepend": true, "cas": true, "delete": true, "incr": true, "decr": true, "touch": true,
	"mg": true, "ms": true, "md": true, "ma": true}

// ParseMemcached reads the verb of a text-protocol command (keys are not kept).
func ParseMemcached(b []byte) (Msg, bool) {
	line, _, ok := bytes.Cut(b, []byte("\r\n"))
	if !ok {
		return Msg{}, false
	}
	verb, _, _ := bytes.Cut(line, []byte(" "))
	if !memcachedVerbs[string(verb)] {
		return Msg{}, false
	}
	return Msg{System: "memcached", Op: string(verb)}, true
}

// IsMemcachedResponse recognises a reply line and whether it is an error.
func IsMemcachedResponse(b []byte) (ok, isErr bool) {
	for _, p := range []string{"VALUE ", "END", "STORED", "NOT_STORED", "EXISTS", "NOT_FOUND", "DELETED", "TOUCHED", "HD", "VA ", "EN", "NF", "NS", "EX"} {
		if bytes.HasPrefix(b, []byte(p)) {
			return true, false
		}
	}
	for _, p := range []string{"ERROR", "CLIENT_ERROR", "SERVER_ERROR"} {
		if bytes.HasPrefix(b, []byte(p)) {
			return true, true
		}
	}
	return len(b) > 0 && b[0] >= '0' && b[0] <= '9' && bytes.HasSuffix(bytes.TrimRight(b, "\x00"), []byte("\r\n")), false
}

// ParseMQTT reads PUBLISH (topic, immediate) and SUBSCRIBE (first topic filter, paired with SUBACK).
func ParseMQTT(b []byte) (Msg, bool) {
	if len(b) < 5 {
		return Msg{}, false
	}
	typ := b[0] >> 4
	if (typ != 3 && typ != 8) || (typ == 8 && b[0]&0x0f != 2) {
		return Msg{}, false
	}
	i, mult, rem := 1, 1, 0 // remaining length varint
	for ; i < 5 && i < len(b); i++ {
		rem += int(b[i]&0x7f) * mult
		mult *= 128
		if b[i]&0x80 == 0 {
			break
		}
	}
	i++
	if rem < 2 || i >= len(b) {
		return Msg{}, false
	}
	if typ == 8 {
		i += 2 // packet id
	}
	if i+2 > len(b) {
		return Msg{}, false
	}
	n := be16(b[i:])
	if n == 0 || i+2+n > len(b) {
		return Msg{}, false
	}
	m := Msg{System: "mqtt", Messaging: true, Dest: string(b[i+2 : i+2+n])}
	if typ == 3 {
		m.Op, m.Immediate = "publish", true
	} else {
		m.Op = "subscribe"
	}
	return m, true
}

// IsMQTTResponse recognises SUBACK; a 0x80 return code is a refusal.
func IsMQTTResponse(b []byte) (ok, isErr bool) {
	return len(b) >= 5 && b[0] == 0x90, len(b) >= 5 && b[4] == 0x80
}

// ParseNATS reads PUB/HPUB (publish) and MSG/HMSG (deliver) lines: the subject only.
func ParseNATS(b []byte) (Msg, bool) {
	line, _, ok := bytes.Cut(b, []byte("\r\n"))
	if !ok {
		return Msg{}, false
	}
	f := bytes.Fields(line)
	if len(f) < 3 {
		return Msg{}, false
	}
	switch string(f[0]) {
	case "PUB", "HPUB":
		return Msg{System: "nats", Op: "publish", Dest: string(f[1]), Immediate: true, Messaging: true}, true
	case "MSG", "HMSG":
		return Msg{System: "nats", Op: "receive", Dest: string(f[1]), Immediate: true, Messaging: true}, true
	}
	return Msg{}, false
}

// ParseAMQP reads AMQP 0-9-1 Basic.Publish (exchange) and Basic.Deliver method frames.
func ParseAMQP(b []byte) (Msg, bool) {
	if len(b) < 12 || b[0] != 1 || be16(b[7:]) != 60 {
		return Msg{}, false
	}
	shortstr := func(i int) (string, int, bool) {
		if i >= len(b) || i+1+int(b[i]) > len(b) {
			return "", i, false
		}
		return string(b[i+1 : i+1+int(b[i])]), i + 1 + int(b[i]), true
	}
	switch be16(b[9:]) {
	case 40: // publish: reserved-1 short, exchange, routing-key
		ex, _, ok := shortstr(13)
		if !ok {
			return Msg{}, false
		}
		return Msg{System: "rabbitmq", Op: "publish", Dest: ex, Immediate: true, Messaging: true}, true
	case 60: // deliver: consumer-tag, delivery-tag u64, redelivered bit, exchange
		_, i, ok := shortstr(11)
		if !ok {
			return Msg{}, false
		}
		ex, _, ok := shortstr(i + 9)
		if !ok {
			return Msg{}, false
		}
		return Msg{System: "rabbitmq", Op: "receive", Dest: ex, Immediate: true, Messaging: true}, true
	}
	return Msg{}, false
}

// ParseTDS reads the text of a SQL Server SQL batch packet (UTF-16LE after ALL_HEADERS).
func ParseTDS(b []byte) (Msg, bool) {
	if len(b) < 14 || b[0] != 0x01 || be16(b[2:]) < 8 {
		return Msg{}, false
	}
	body := b[8:]
	if h := int(binary.LittleEndian.Uint32(body)); h >= 4 && h < len(body) && h <= 1024 {
		body = body[h:]
	}
	u := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body) && len(u) < maxStmt; i += 2 {
		u = append(u, binary.LittleEndian.Uint16(body[i:]))
	}
	s := string(utf16.Decode(u))
	if len(s) < 4 {
		return Msg{}, false
	}
	return Msg{System: "mssql", Stmt: s}, true
}

// IsTDSResponse recognises a tabular result packet; an ERROR token (0xAA) marks failure.
func IsTDSResponse(b []byte) (ok, isErr bool) {
	return len(b) >= 9 && b[0] == 0x04, len(b) >= 9 && bytes.IndexByte(b[8:], 0xAA) == 0
}

// otherParsers are tried, in order, on a request head no HTTP/SQL/Redis parser claimed.
var otherParsers = []func([]byte) (Msg, bool){ParseMemcached, ParseMQTT, ParseNATS, ParseAMQP, ParseTDS}

// strictBinary tries the protocols whose headers are checked tightly (Kafka, MongoDB).
func strictBinary(b []byte) (Msg, bool) {
	if m, ok := ParseMongo(b); ok {
		return m, true
	}
	return ParseKafka(b)
}

// applyMsg fills a pending span from a parsed message.
func applyMsg(p *pending, m Msg, c *conn) {
	if m.Stmt != "" {
		setDB(p, m.System, m.Stmt, false, c)
		return
	}
	p.proto, p.corr = m.System, m.Corr
	p.Name = m.Op
	if m.Dest != "" {
		p.Name = m.Op + " " + m.Dest
	}
	if m.Messaging {
		p.Attrs["messaging.system"] = m.System
		p.Attrs["messaging.operation.name"] = m.Op
		if m.Dest != "" {
			p.Attrs["messaging.destination.name"] = m.Dest
		}
		return
	}
	p.Attrs["db.system"] = m.System
	p.Attrs["db.operation.name"] = m.Op
	if m.Dest != "" {
		p.Attrs["db.collection.name"] = m.Dest
	}
}

// otherResponse completes a pending span of one of these protocols.
func otherResponse(p *pending, b []byte) (ok, isErr bool) {
	switch p.proto {
	case "kafka":
		return IsKafkaResponse(b, p.corr), false
	case "mongodb":
		return IsMongoResponse(b, p.corr)
	case "memcached":
		return IsMemcachedResponse(b)
	case "mqtt":
		return IsMQTTResponse(b)
	case "mssql":
		return IsTDSResponse(b)
	}
	return false, false
}
