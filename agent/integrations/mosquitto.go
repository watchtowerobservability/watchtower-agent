package integrations

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MQTTConfig is the mosquitto module's config. Addr and the credentials are local-file only.
type MQTTConfig struct {
	Base
	Addr     string `json:"addr"` // host:port of an MQTT listener, usually 127.0.0.1:1883
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      bool   `json:"tls"`
}

func (c *MQTTConfig) check() error {
	if c.Addr == "" {
		return errors.New("mosquitto: addr is required (in the agent's own config file)")
	}
	return nil
}

// mosquittoSys maps $SYS topics to series; the bool marks cumulative counters.
var mosquittoSys = map[string]struct {
	name, unit string
	sum        bool
}{
	"$SYS/broker/clients/connected":         {"mosquitto.clients.connected", "{clients}", false},
	"$SYS/broker/clients/disconnected":      {"mosquitto.clients.disconnected", "{clients}", false}, // persistent sessions offline
	"$SYS/broker/clients/maximum":           {"mosquitto.clients.maximum", "{clients}", false},
	"$SYS/broker/clients/total":             {"mosquitto.clients.total", "{clients}", false},
	"$SYS/broker/clients/expired":           {"mosquitto.clients.expired", "{clients}", true},
	"$SYS/broker/messages/received":         {"mosquitto.messages.received", "{messages}", true},
	"$SYS/broker/messages/sent":             {"mosquitto.messages.sent", "{messages}", true},
	"$SYS/broker/messages/stored":           {"mosquitto.messages.stored", "{messages}", false},
	"$SYS/broker/publish/messages/dropped":  {"mosquitto.publish.dropped", "{messages}", true},
	"$SYS/broker/publish/messages/received": {"mosquitto.publish.received", "{messages}", true},
	"$SYS/broker/publish/messages/sent":     {"mosquitto.publish.sent", "{messages}", true},
	"$SYS/broker/bytes/received":            {"mosquitto.bytes.received", "By", true},
	"$SYS/broker/bytes/sent":                {"mosquitto.bytes.sent", "By", true},
	"$SYS/broker/subscriptions/count":       {"mosquitto.subscriptions", "{subscriptions}", false},
	"$SYS/broker/retained messages/count":   {"mosquitto.retained_messages", "{messages}", false},
	"$SYS/broker/store/messages/count":      {"mosquitto.store.messages", "{messages}", false},
	"$SYS/broker/store/messages/bytes":      {"mosquitto.store.bytes", "By", false},
	"$SYS/broker/heap/current":              {"mosquitto.heap.current", "By", false}, // only with memory tracking
	"$SYS/broker/uptime":                    {"mosquitto.uptime", "s", false},        // "1234 seconds"
}

// Mosquitto subscribes to $SYS/# over MQTT 3.1.1 and reads the broker's statistics (Mosquitto
// publishes them retained, every sys_interval). Bridge state topics
// ($SYS/broker/connection/<name>/state) become mosquitto.bridge.up.
func Mosquitto(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &MQTTConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "mosquitto", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		sys, err := readSys(ctx, *c, 3*time.Second)
		if err != nil {
			return err
		}
		EmitMosquittoSys(out, sys, now)
		return nil
	})
}

// readSys connects, subscribes to $SYS/# and collects topic values until quiet for 500 ms
// (retained values arrive at once) or wait ends.
func readSys(ctx context.Context, c MQTTConfig, wait time.Duration) (map[string]string, error) {
	conn, err := dial(ctx, c.Addr, c.TLS)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(mqttPacket(0x10, mqttConnectBody("wt-agent-"+strconv.FormatInt(time.Now().UnixNano()%1e9, 36), c.Username, c.Password))); err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	typ, body, err := mqttRead(r)
	if err != nil {
		return nil, err
	}
	if typ != 0x20 || len(body) < 2 {
		return nil, errors.New("mosquitto: the reply is not a CONNACK")
	}
	if body[1] != 0 {
		return nil, fmt.Errorf("mosquitto: connection refused (return code %d)", body[1])
	}
	sub := append([]byte{0, 1}, mqttString("$SYS/#")...)
	if _, err := conn.Write(mqttPacket(0x82, append(sub, 0))); err != nil {
		return nil, err
	}
	sys := map[string]string{}
	for len(sys) < 1000 {
		_ = conn.SetReadDeadline(minTime(deadline, time.Now().Add(500*time.Millisecond)))
		typ, body, err := mqttRead(r)
		if err != nil {
			break // quiet or deadline: what arrived is the round
		}
		if typ&0xF0 != 0x30 || len(body) < 2 {
			continue // SUBACK, PINGRESP
		}
		n := int(body[0])<<8 | int(body[1])
		if len(body) < 2+n {
			continue
		}
		payload := body[2+n:]
		if qos := (typ >> 1) & 3; qos > 0 && len(payload) >= 2 {
			payload = payload[2:] // packet id
		}
		sys[string(body[2:2+n])] = string(payload)
	}
	_, _ = conn.Write([]byte{0xE0, 0}) // DISCONNECT
	if len(sys) == 0 {
		return nil, errors.New("mosquitto: no $SYS topics (sys_interval 0, or the user may not read $SYS/#)")
	}
	return sys, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func mqttString(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...) }

// mqttConnectBody is an MQTT 3.1.1 CONNECT (clean session, 30 s keep-alive).
func mqttConnectBody(clientID, user, pass string) []byte {
	flags := byte(0x02)
	payload := mqttString(clientID)
	if user != "" {
		flags |= 0x80
		payload = append(payload, mqttString(user)...)
		if pass != "" {
			flags |= 0x40
			payload = append(payload, mqttString(pass)...)
		}
	}
	return append(append(mqttString("MQTT"), 4, flags, 0, 30), payload...)
}

// mqttPacket frames body with its fixed header (remaining length: 7 bits per byte).
func mqttPacket(typ byte, body []byte) []byte {
	pkt := []byte{typ}
	for n := len(body); ; {
		b := byte(n % 128)
		if n /= 128; n > 0 {
			b |= 0x80
		}
		pkt = append(pkt, b)
		if n == 0 {
			break
		}
	}
	return append(pkt, body...)
}

// mqttRead reads one packet (at most 64 KiB, plenty for $SYS values).
func mqttRead(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, mul := 0, 1
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, nil, err
		}
		n += int(b&0x7F) * mul
		if b&0x80 == 0 {
			break
		}
		if mul *= 128; i == 3 {
			return 0, nil, errors.New("mqtt: bad remaining length")
		}
	}
	if n > 64<<10 {
		return 0, nil, errors.New("mqtt: packet too large")
	}
	body := make([]byte, n)
	_, err = io.ReadFull(r, body)
	return typ, body, err
}

// EmitMosquittoSys turns $SYS topic values into series.
func EmitMosquittoSys(out sink.Sink, sys map[string]string, now time.Time) {
	for topic, v := range sys {
		if name, ok := strings.CutPrefix(topic, "$SYS/broker/connection/"); ok && strings.HasSuffix(name, "/state") {
			out.Gauge("mosquitto.bridge.up", "1", b2f(strings.TrimSpace(v) == "1"),
				map[string]string{"bridge": strings.TrimSuffix(name, "/state")}, now)
			continue
		}
		m, ok := mosquittoSys[topic]
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(v), " seconds"), 64)
		if err != nil {
			continue
		}
		if m.sum {
			out.Sum(m.name, m.unit, f, nil, now)
		} else {
			out.Gauge(m.name, m.unit, f, nil, now)
		}
	}
}
