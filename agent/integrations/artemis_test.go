package integrations

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func jolokiaFixture(t *testing.T, name string) []jolokiaResp {
	t.Helper()
	b, err := os.ReadFile("testdata/jolokia/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var rs []jolokiaResp
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestArtemisBrokerAndQueues(t *testing.T) {
	r := &sink.Recorder{}
	emitArtemis(r, jolokiaFixture(t, "artemis.json"), time.Now())
	b := map[string]string{"broker": "0.0.0.0"}
	wantSample(t, r, "artemis.broker.address_memory.percent", b, 93)
	wantSample(t, r, "artemis.broker.replica_sync", b, 0)
	wantSample(t, r, "artemis.broker.active", b, 1)
	orders := map[string]string{"address": "orders", "queue": "orders", "routing_type": "anycast"}
	wantSample(t, r, "artemis.queue.messages", orders, 1500)
	wantSample(t, r, "artemis.queue.oldest_message_age", orders, 360)
	wantSample(t, r, "artemis.queue.messages.killed", orders, 12)
	wantSample(t, r, "artemis.queue.paused", map[string]string{"queue": "DLQ"}, 1)
	if _, ok := sample(r, "artemis.queue.oldest_message_age", map[string]string{"queue": "empty"}); ok {
		t.Error("an empty queue has no first message age")
	}
}

func TestActiveMQBrokerUsageAndQueueTimes(t *testing.T) {
	r := &sink.Recorder{}
	emitActiveMQ(r, jolokiaFixture(t, "activemq.json"), time.Now())
	wantSample(t, r, "activemq.broker.store_percent", map[string]string{"broker": "localhost"}, 88)
	wantSample(t, r, "activemq.broker.connections.created", map[string]string{"broker": "localhost"}, 77)
	wantSample(t, r, "activemq.queue.enqueue_time.max", map[string]string{"queue": "orders"}, 9000)
	wantSample(t, r, "activemq.queue.size", map[string]string{"queue": "ActiveMQ.DLQ"}, 7)
	if _, ok := sample(r, "activemq.queue.size", map[string]string{"queue": ""}); ok {
		t.Error("the broker MBean must not become a queue")
	}
}
