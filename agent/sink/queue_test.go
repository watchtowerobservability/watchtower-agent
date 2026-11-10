package sink

import (
	"testing"
	"time"
)

func find(r *Recorder, name string, want map[string]string) (float64, bool) {
next:
	for _, s := range r.Snapshot() {
		if s.Name != name {
			continue
		}
		for k, v := range want {
			if s.Attrs[k] != v {
				continue next
			}
		}
		return s.Value, true
	}
	return 0, false
}

func TestQueueContractMapsEveryBroker(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		attrs   map[string]string
		v       float64
		metric  string
		want    map[string]string
		wantVal float64
	}{
		{"rabbitmq.queue.ready", map[string]string{"queue": "orders", "vhost": "/"}, 115, QueueDepth, map[string]string{"queue": "orders", "framework": "rabbitmq", "state": "ready", "vhost": "/"}, 115},
		{"rabbitmq.queue.oldest_message_age", map[string]string{"queue": "orders"}, 600, QueueAge, map[string]string{"queue": "orders", "framework": "rabbitmq"}, 600},
		{"activemq.queue.size", map[string]string{"queue": "orders", "broker": "b1"}, 12, QueueDepth, map[string]string{"framework": "activemq", "state": "ready", "broker": "b1"}, 12},
		{"artemis.queue.delivering", map[string]string{"queue": "q", "broker": "b"}, 4, QueueDepth, map[string]string{"framework": "artemis", "state": "unacked"}, 4},
		{"nats.jetstream.consumer.ack_pending", map[string]string{"stream": "ORDERS", "consumer": "billing"}, 950, QueueDepth, map[string]string{"queue": "ORDERS", "group": "", "consumer": "billing", "state": "unacked"}, 950},
		{"pulsar.subscription.backlog", map[string]string{"topic": "persistent://t/n/x", "subscription": "s"}, 5, QueueDepth, map[string]string{"queue": "persistent://t/n/x", "framework": "pulsar", "subscription": "s"}, 5},
		{"kafka.consumer_group.lag_sum", map[string]string{"topic": "orders", "group": "billing"}, 70, QueueDepth, map[string]string{"queue": "orders", "framework": "kafka", "group": "billing"}, 70},
		{"kafka.consumer_group.lag_time", map[string]string{"topic": "orders", "group": "billing"}, 3, QueueLag, map[string]string{"queue": "orders", "framework": "kafka"}, 3},
		{"redis.stream.group.pending", map[string]string{"stream": "jobs", "group": "g"}, 2, QueueDepth, map[string]string{"queue": "jobs", "framework": "redis", "state": "unacked"}, 2},
		{"amazonaws.com/AWS/SQS/ApproximateAgeOfOldestMessage", map[string]string{"aws.dim.QueueName": "orders-dlq", "resource.cloud.region": "eu-west-1"}, 90, QueueAge, map[string]string{"queue": "orders-dlq", "framework": "sqs", "resource.cloud.region": "eu-west-1"}, 90},
		{"amazonaws.com/AWS/Kinesis/GetRecords.IteratorAgeMilliseconds", map[string]string{"aws.dim.StreamName": "clicks"}, 4500, QueueLag, map[string]string{"queue": "clicks", "framework": "kinesis"}, 4.5},
		{"cloud.azure.microsoft.servicebus.namespaces.deadletteredmessages", map[string]string{"azure.entity": "invoices"}, 3, QueueDepth, map[string]string{"queue": "invoices", "framework": "servicebus", "state": "dead"}, 3},
		{"cloud.azure.microsoft.servicebus.namespaces.activemessages", map[string]string{ResourcePrefix + "cloud.resource_id": "ns1"}, 8, QueueDepth, map[string]string{"queue": "ns1", "state": "ready"}, 8},
		{"cloud.gcp.pubsub.subscription.num_undelivered_messages", map[string]string{"gcp.resource.subscription_id": "sub1"}, 31, QueueDepth, map[string]string{"queue": "sub1", "framework": "pubsub", "state": "ready"}, 31},
	}
	for _, c := range cases {
		r := &Recorder{}
		QueueContract(r).Gauge(c.name, "", c.v, c.attrs, now)
		if _, ok := find(r, c.name, nil); !ok {
			t.Errorf("%s: the native series must still be written", c.name)
		}
		if v, ok := find(r, c.metric, c.want); !ok || v != c.wantVal {
			t.Errorf("%s: %s%v = %v %v, want %v (%+v)", c.name, c.metric, c.want, v, ok, c.wantVal, r.Snapshot())
		}
	}
}

func TestQueueContractSkipsNamelessAndOtherMetrics(t *testing.T) {
	r := &Recorder{}
	q := QueueContract(r)
	q.Gauge("rabbitmq.queue.ready", "", 1, map[string]string{"vhost": "/"}, time.Now())
	q.Gauge("rabbitmq.queue.ready", "", 1, map[string]string{"queue": "*"}, time.Now())
	q.Gauge("nats.connections", "", 1, nil, time.Now())
	if len(r.Snapshot()) != 3 {
		t.Fatalf("only the native points expected: %+v", r.Snapshot())
	}
	if QueueContract(q) != q {
		t.Fatal("wrapping twice must not double the series")
	}
}
