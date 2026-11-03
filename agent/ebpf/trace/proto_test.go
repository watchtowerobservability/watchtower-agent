package trace

import (
	"encoding/binary"
	"testing"
	"time"
)

func kafkaProduce(topic string, corr int32) []byte {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 7} // size (patched), api key 0, version 7
	b = binary.BigEndian.AppendUint32(b, uint32(corr))
	b = append(b, 0, 3, 'c', 'l', 'i', 0xff, 0xff) // client_id "cli", null transactional_id
	b = append(b, 0, 1, 0, 0, 0x75, 0x30)          // acks, timeout
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, 0, byte(len(topic)))
	b = append(b, topic...)
	binary.BigEndian.PutUint32(b, uint32(len(b)-4))
	return b
}

func TestKafkaProduceSpanPairsByCorrelation(t *testing.T) {
	a := NewAssembler()
	t0 := time.Unix(100, 0)
	if _, ok := a.Handle(Event{TS: t0, PID: 1, FD: 3, Dir: Send, Data: kafkaProduce("orders", 42)}); ok {
		t.Fatal("request alone must not finish")
	}
	resp := binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, 41)
	if _, ok := a.Handle(Event{TS: t0.Add(time.Millisecond), PID: 1, FD: 3, Dir: Recv, Data: resp}); ok {
		t.Fatal("another correlation id must not finish the span")
	}
	resp = binary.BigEndian.AppendUint32([]byte{0, 0, 0, 8}, 42)
	sp, ok := a.Handle(Event{TS: t0.Add(2 * time.Millisecond), PID: 1, FD: 3, Dir: Recv, Data: resp})
	if !ok || sp.Name != "publish orders" || sp.Attrs["messaging.system"] != "kafka" || sp.Attrs["messaging.destination.name"] != "orders" || !sp.Client {
		t.Fatalf("span %+v %v", sp, ok)
	}
}

func TestFireAndForgetAndTextProtocols(t *testing.T) {
	a := NewAssembler()
	now := time.Unix(5, 0)
	sp, ok := a.Handle(Event{TS: now, PID: 2, FD: 4, Dir: Send, Data: []byte("PUB orders.created 11\r\n{\"id\":1}\r\n")})
	if !ok || sp.Name != "publish orders.created" || sp.Attrs["messaging.system"] != "nats" {
		t.Fatalf("nats: %+v", sp)
	}
	mqtt := []byte{0x30, 9, 0, 3, 'a', '/', 'b', 'h', 'i', '!', '!'}
	if sp, ok = a.Handle(Event{TS: now, PID: 2, FD: 5, Dir: Send, Data: mqtt}); !ok || sp.Attrs["messaging.destination.name"] != "a/b" {
		t.Fatalf("mqtt: %+v", sp)
	}
	amqp := []byte{1, 0, 1, 0, 0, 0, 20, 0, 60, 0, 40, 0, 0, 3, 'e', 'v', 't', 2, 'r', 'k'}
	if sp, ok = a.Handle(Event{TS: now, PID: 2, FD: 6, Dir: Send, Data: amqp}); !ok || sp.Name != "publish evt" {
		t.Fatalf("amqp: %+v", sp)
	}
	a.Handle(Event{TS: now, PID: 2, FD: 7, Dir: Send, Data: []byte("get user:42\r\n")})
	if sp, ok = a.Handle(Event{TS: now, PID: 2, FD: 7, Dir: Recv, Data: []byte("END\r\n")}); !ok || sp.Name != "get" || sp.Attrs["db.system"] != "memcached" {
		t.Fatalf("memcached: %+v", sp)
	}
}

func TestMongoAndTDS(t *testing.T) {
	doc := []byte{0, 0, 0, 0, 0x02, 'f', 'i', 'n', 'd', 0, 6, 0, 0, 0, 'u', 's', 'e', 'r', 's', 0, 0}
	msg := make([]byte, 21)
	binary.LittleEndian.PutUint32(msg[4:], 77)
	binary.LittleEndian.PutUint32(msg[12:], mongoOpMsg)
	msg = append(msg, doc...)
	binary.LittleEndian.PutUint32(msg, uint32(len(msg)))
	m, ok := ParseMongo(msg)
	if !ok || m.Op != "find" || m.Dest != "users" || m.Corr != 77 {
		t.Fatalf("mongo: %+v %v", m, ok)
	}
	rep := make([]byte, 16)
	binary.LittleEndian.PutUint32(rep[8:], 77)
	binary.LittleEndian.PutUint32(rep[12:], mongoOpMsg)
	if ok, isErr := IsMongoResponse(append(rep, "errmsg\x00"...), 77); !ok || !isErr {
		t.Fatal("mongo error reply")
	}
	tds := []byte{0x01, 0x01, 0, 0, 0, 0, 1, 0, 4, 0, 0, 0}
	for _, r := range "SELECT 1" {
		tds = append(tds, byte(r), 0)
	}
	binary.BigEndian.PutUint16(tds[2:], uint16(len(tds)))
	if m, ok := ParseTDS(tds); !ok || m.Stmt != "SELECT 1" {
		t.Fatalf("tds: %+v %v", m, ok)
	}
}
