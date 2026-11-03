package integrations

import (
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The queues page reads cluster > broker > topic from these series: brokers with their rack and
// controller flag, partitions led per broker and topic, and the cluster label on every series.
func TestKafkaBrokerTopology(t *testing.T) {
	rack := "eu-1a"
	md := kadm.Metadata{Cluster: "kc1", Controller: 2, Brokers: kadm.BrokerDetails{
		kgo.BrokerMetadata{NodeID: 1, Host: "b1", Port: 9092, Rack: &rack}, kgo.BrokerMetadata{NodeID: 2, Host: "b2", Port: 9092},
	}}
	topics := kadm.TopicDetails{"orders": {Topic: "orders", Partitions: kadm.PartitionDetails{
		0: {Partition: 0, Leader: 1}, 1: {Partition: 1, Leader: 2}, 2: {Partition: 2, Leader: 1}, 3: {Partition: 3, Leader: -1},
	}}}
	rec := &sink.Recorder{}
	out := clusterSink{Sink: rec, cluster: md.Cluster}
	emitBrokers(out, md, topics, time.Now())
	out.Gauge("kafka.consumer_group.lag_sum", "{messages}", 5, map[string]string{"group": "g", "topic": "orders"}, time.Now())
	led := map[string]float64{}
	for _, s := range rec.Samples {
		if s.Attrs["cluster"] != "kc1" {
			t.Fatalf("%s has no cluster label: %v", s.Name, s.Attrs)
		}
		switch s.Name {
		case "kafka.broker.info":
			if s.Attrs["broker"] == "1" && (s.Attrs["rack"] != "eu-1a" || s.Attrs["controller"] != "false") ||
				s.Attrs["broker"] == "2" && s.Attrs["controller"] != "true" {
				t.Fatalf("broker info: %v", s.Attrs)
			}
		case "kafka.broker.partitions_led":
			led[s.Attrs["broker"]] = s.Value
		}
	}
	if len(led) != 2 || led["1"] != 2 || led["2"] != 1 {
		t.Fatalf("partitions led: %v", led)
	}
	if got := (clusterSink{Sink: rec}).with(map[string]string{"a": "b"}); len(got) != 1 {
		t.Fatalf("no cluster id adds no label: %v", got)
	}
}
