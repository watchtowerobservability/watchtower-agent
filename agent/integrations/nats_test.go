package integrations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestNATSJetStreamFixtures(t *testing.T) {
	srv := fixtureServer(t, "nats", map[string]string{"/varz": "varz.json", "/jsz": "jsz.json"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := &sink.Recorder{}
	_ = NATS(ctx, json.RawMessage(`{"url":"`+srv.URL+`"}`), r)
	wantSample(t, r, "nats.subscriptions", nil, 88)
	wantSample(t, r, "nats.jetstream.api.errors", nil, 7)
	wantSample(t, r, "nats.jetstream.storage.limit", nil, 10737418240)
	orders := map[string]string{"account": "APP", "stream": "ORDERS"}
	wantSample(t, r, "nats.jetstream.stream.messages", orders, 40000)
	wantSample(t, r, "nats.jetstream.stream.replicas_lagging", orders, 1)
	wantSample(t, r, "nats.jetstream.stream.info", map[string]string{"stream": "KV_sessions", "kind": "kv", "bucket": "sessions"}, 1)
	wantSample(t, r, "nats.jetstream.stream.info", map[string]string{"stream": "OBJ_assets", "kind": "object", "bucket": "assets"}, 1)
	billing := map[string]string{"stream": "ORDERS", "consumer": "billing"}
	wantSample(t, r, "nats.jetstream.consumer.ack_pending", billing, 950)
	wantSample(t, r, "nats.jetstream.consumer.redelivered", billing, 14)
	wantSample(t, r, "nats.jetstream.consumer.pending", billing, 50)
	wantSample(t, r, "nats.jetstream.consumer.delivered", billing, 39950)
	wantSample(t, r, "nats.jetstream.consumer.waiting", map[string]string{"consumer": "audit"}, 2)
	if _, ok := sample(r, "nats.jetstream.consumer.ack_floor_age", map[string]string{"consumer": "audit"}); ok {
		t.Error("a caught-up consumer has no ack floor age")
	}
	wantSample(t, r, "wt.integration.up", map[string]string{"integration": "nats"}, 1)
}

func TestNATSAckFloorAge(t *testing.T) {
	b := []byte(`{"account_details":[{"name":"A","stream_detail":[{"name":"S","consumer_detail":[
		{"name":"c","num_ack_pending":3,"ack_floor":{"last_active":"2026-11-02T12:05:00Z"}}]}]}]}`)
	r := &sink.Recorder{}
	if err := EmitNATSJsz(r, b, time.Date(2026, 11, 2, 12, 10, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	wantSample(t, r, "nats.jetstream.consumer.ack_floor_age", map[string]string{"consumer": "c"}, 300)
}
