package integrations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestPulsarBacklogAgeFromAdminStats(t *testing.T) {
	srv := fixtureServer(t, "pulsar", map[string]string{
		"/metrics": "metrics.txt", "/admin/v2/persistent/public/default/orders/stats": "orders_stats.json",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := &sink.Recorder{}
	_ = Pulsar(ctx, json.RawMessage(`{"url":"`+srv.URL+`"}`), r)
	wantNames(t, r, "pulsar_subscription_back_log", "pulsar_msg_backlog")
	if r.Names()["jvm_memory_bytes_used"] {
		t.Error("families outside the prefix are not forwarded")
	}
	billing := map[string]string{"topic": "persistent://public/default/orders", "subscription": "billing"}
	if v, ok := sample(r, "pulsar.subscription.backlog_age", billing); !ok || v < 600 {
		t.Errorf("backlog_age %v %v (earliest message is from 1793620000)", v, ok)
	}
	wantSample(t, r, "pulsar.subscription.blocked_on_unacked", billing, 1)
	wantSample(t, r, "pulsar.subscription.backlog_age", map[string]string{"subscription": "audit"}, 0)
	wantSample(t, r, "pulsar.subscription.consumers", map[string]string{"subscription": "audit"}, 2)
}

func TestPulsarStatsAtFixedTime(t *testing.T) {
	r := &sink.Recorder{}
	b := []byte(`{"subscriptions":{"s":{"msgBacklog":5,"earliestMsgPublishTimeInBacklog":1000000,"lastAckedTimestamp":1060000}}}`)
	if err := EmitPulsarTopicStats(r, "persistent://t/n/x", b, time.UnixMilli(1120000)); err != nil {
		t.Fatal(err)
	}
	wantSample(t, r, "pulsar.subscription.backlog_age", nil, 120)
	wantSample(t, r, "pulsar.subscription.last_ack_age", nil, 60)
	if got := pulsarTopicPath("persistent://my tenant/ns/a/b"); got != "persistent/my%20tenant/ns/a/b" {
		t.Fatalf("path %q", got)
	}
}
