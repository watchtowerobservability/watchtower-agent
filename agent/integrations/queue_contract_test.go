package integrations

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The brokers' own collectors, run against recorded management and admin API answers through
// the contract wrapper, feed the Queues area's depth, oldest-age and lag series.

func TestRabbitMQFeedsTheQueuesArea(t *testing.T) {
	srv := fixtureServer(t, "rabbitmq", map[string]string{
		"/api/queues": "queues.json", "/api/overview": "overview.json",
	})
	r := &sink.Recorder{}
	if err := collectRabbit(context.Background(), HTTPConfig{URL: srv.URL}, sink.QueueContract(r), time.Unix(1793620600, 0)); err != nil {
		t.Fatal(err)
	}
	orders := map[string]string{"queue": "orders", "framework": "rabbitmq", "vhost": "/"}
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(orders, "state", "ready"), 115)
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(orders, "state", "unacked"), 5)
	wantSample(t, r, "messaging.queue.oldest_age_seconds", orders, 600)
}

func mergeAttrs(m map[string]string, kv ...string) map[string]string {
	o := map[string]string{}
	for k, v := range m {
		o[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		o[kv[i]] = kv[i+1]
	}
	return o
}

func TestActiveMQAndArtemisFeedTheQueuesArea(t *testing.T) {
	r := &sink.Recorder{}
	emitArtemis(sink.QueueContract(r), jolokiaFixture(t, "artemis.json"), time.Now())
	art := map[string]string{"queue": "orders", "framework": "artemis"}
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(art, "state", "ready"), 1500)
	wantSample(t, r, "messaging.queue.oldest_age_seconds", art, 360)

	rs := []jolokiaResp{{Status: 200, Value: json.RawMessage(`{
	 "org.apache.activemq:brokerName=b1,destinationName=orders,destinationType=Queue,type=Broker":{"QueueSize":12,"InFlightCount":3}}`)}}
	rs[0].Request.MBean = activemqReads[0].MBean
	emitActiveMQ(sink.QueueContract(r), rs, time.Now())
	amq := map[string]string{"queue": "orders", "framework": "activemq", "broker": "b1"}
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(amq, "state", "ready"), 12)
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(amq, "state", "unacked"), 3)
}

func TestNATSJetStreamConsumersFeedTheQueuesArea(t *testing.T) {
	srv := fixtureServer(t, "nats", map[string]string{"/varz": "varz.json", "/jsz": "jsz.json"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := &sink.Recorder{}
	_ = NATS(ctx, json.RawMessage(`{"url":"`+srv.URL+`"}`), sink.QueueContract(r))
	c := map[string]string{"queue": "ORDERS", "framework": "nats", "consumer": "billing"}
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(c, "state", "unacked"), 950)
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(c, "state", "ready"), 50)
}

func TestPulsarAdminStatsFeedTheQueuesArea(t *testing.T) {
	r := &sink.Recorder{}
	b := []byte(`{"subscriptions":{"billing":{"msgBacklog":5,"unackedMessages":2,"earliestMsgPublishTimeInBacklog":1000000,"lastAckedTimestamp":1060000}}}`)
	if err := EmitPulsarTopicStats(sink.QueueContract(r), "persistent://t/n/orders", b, time.UnixMilli(1120000)); err != nil {
		t.Fatal(err)
	}
	p := map[string]string{"queue": "persistent://t/n/orders", "framework": "pulsar", "subscription": "billing"}
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(p, "state", "ready"), 5)
	wantSample(t, r, "messaging.queue.depth", mergeAttrs(p, "state", "unacked"), 2)
	wantSample(t, r, "messaging.queue.oldest_age_seconds", p, 120)
}
