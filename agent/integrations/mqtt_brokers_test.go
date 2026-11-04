package integrations

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// fakeMosquitto accepts one MQTT session: CONNACK, SUBACK, then the recorded `mosquitto_sub -v
// -t '$SYS/#'` lines of testdata/mosquitto/sys.txt as retained PUBLISH packets.
func fakeMosquitto(t *testing.T, refuse byte) string {
	t.Helper()
	lines, err := os.ReadFile("testdata/mosquitto/sys.txt")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		if typ, body, err := mqttRead(r); err != nil || typ != 0x10 || !strings.Contains(string(body), "MQTT") {
			return
		}
		_, _ = c.Write([]byte{0x20, 2, 0, refuse})
		if typ, body, err := mqttRead(r); err != nil || typ != 0x82 || !strings.Contains(string(body), "$SYS/#") {
			return
		}
		_, _ = c.Write([]byte{0x90, 3, 0, 1, 0})
		for _, l := range strings.Split(strings.TrimSpace(string(lines)), "\n") {
			// a topic may hold spaces ("retained messages/count"): it ends at the first space not followed by a path segment
			i := strings.Index(l, " ")
			for i >= 0 && strings.Contains(strings.SplitN(l[i+1:], " ", 2)[0], "/") {
				j := strings.Index(l[i+1:], " ")
				if j < 0 {
					break
				}
				i += j + 1
			}
			topic, payload := l[:i], l[i+1:]
			_, _ = c.Write(mqttPacket(0x31, append(mqttString(topic), payload...)))
		}
		_, _, _ = mqttRead(r) // DISCONNECT
	}()
	return ln.Addr().String()
}

func TestMosquittoSysFromRecordedTopics(t *testing.T) {
	sys, err := readSys(context.Background(), MQTTConfig{Addr: fakeMosquitto(t, 0), Username: "wt", Password: "p"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := &sink.Recorder{}
	EmitMosquittoSys(r, sys, time.Now())
	wantSample(t, r, "mosquitto.clients.connected", nil, 48)
	wantSample(t, r, "mosquitto.publish.dropped", nil, 37)
	wantSample(t, r, "mosquitto.uptime", nil, 86400)
	wantSample(t, r, "mosquitto.retained_messages", nil, 1250)
	wantSample(t, r, "mosquitto.bridge.up", map[string]string{"bridge": "edge-to-cloud"}, 1)
	wantSample(t, r, "mosquitto.bridge.up", map[string]string{"bridge": "backup-dc"}, 0)
	if r.Names()["mosquitto.version"] {
		t.Error("a text topic is not a series")
	}
	if _, err := readSys(context.Background(), MQTTConfig{Addr: fakeMosquitto(t, 5)}, time.Second); err == nil {
		t.Fatal("CONNACK 5 (not authorized) must fail the round")
	}
}

func TestMQTTRemainingLengthRoundTrip(t *testing.T) {
	body := make([]byte, 20000)
	typ, got, err := mqttRead(bufio.NewReader(strings.NewReader(string(mqttPacket(0x30, body)))))
	if err != nil || typ != 0x30 || len(got) != 20000 {
		t.Fatalf("%x %d %v", typ, len(got), err)
	}
	if _, _, err := mqttRead(bufio.NewReader(strings.NewReader("\x30\xff\xff\xff\xff\x01"))); err == nil {
		t.Fatal("a five-byte remaining length must be refused")
	}
}

func TestEMQXFixtures(t *testing.T) {
	srv := fixtureServer(t, "emqx", map[string]string{"/api/v5/stats": "stats.json", "/api/v5/metrics": "metrics.json",
		"/api/v5/nodes": "nodes.json", "/api/v5/alarms": "alarms.json"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := &sink.Recorder{}
	_ = EMQX(ctx, json.RawMessage(`{"url":"`+srv.URL+`","username":"key","password":"secret"}`), r)
	wantSample(t, r, "wt.integration.up", map[string]string{"integration": "emqx"}, 1)
	wantSample(t, r, "emqx.connections", nil, 120)
	wantSample(t, r, "emqx.connections.max", nil, 340)
	wantSample(t, r, "emqx.messages.dropped.no_subscribers", nil, 15)
	wantSample(t, r, "emqx.delivery.dropped.queue_full", nil, 30)
	wantSample(t, r, "emqx.client.auth.failure", nil, 17)
	wantSample(t, r, "emqx.node.running", map[string]string{"node": "emqx@10.0.0.12"}, 0)
	wantSample(t, r, "emqx.node.memory.used", map[string]string{"node": "emqx@10.0.0.11"}, 402653184)
	if _, ok := sample(r, "emqx.node.memory.used", map[string]string{"node": "emqx@10.0.0.12"}); ok {
		t.Error("a \"0.00M\" string is not a byte count")
	}
	wantSample(t, r, "emqx.alarms.active", nil, 3)
	wantSample(t, r, "emqx.alarm.active", map[string]string{"alarm": "conn_congestion"}, 2)
}
