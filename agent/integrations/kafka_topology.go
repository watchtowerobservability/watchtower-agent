package integrations

import (
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The queues page (INF-040) draws cluster > broker > topic > consumer group from these series:
// every kafka.* series carries `cluster` (the cluster id), brokers report kafka.broker.info and
// the partitions they lead, so a topic links to the brokers leading its partitions.

// clusterSink adds the cluster label to every series it forwards.
type clusterSink struct {
	sink.Sink
	cluster string
}

func (c clusterSink) with(a map[string]string) map[string]string {
	if c.cluster == "" {
		return a
	}
	m := make(map[string]string, len(a)+1)
	for k, v := range a {
		m[k] = v
	}
	m["cluster"] = c.cluster
	return m
}

func (c clusterSink) Gauge(name, unit string, v float64, a map[string]string, at time.Time) {
	c.Sink.Gauge(name, unit, v, c.with(a), at)
}

func (c clusterSink) Sum(name, unit string, v float64, a map[string]string, at time.Time) {
	c.Sink.Sum(name, unit, v, c.with(a), at)
}

// emitBrokers writes kafka.broker.info (1 per broker; host, rack, controller) and, per broker
// and topic, kafka.broker.partitions_led (at most MaxKafkaTopics topics, like partition health).
func emitBrokers(out sink.Sink, md kadm.Metadata, topics kadm.TopicDetails, now time.Time) {
	for _, b := range md.Brokers {
		rack := ""
		if b.Rack != nil {
			rack = *b.Rack
		}
		out.Gauge("kafka.broker.info", "1", 1, map[string]string{"broker": strconv.Itoa(int(b.NodeID)), "host": b.Host,
			"rack": rack, "controller": strconv.FormatBool(b.NodeID == md.Controller)}, now)
	}
	n := 0
	for _, t := range topics.Sorted() {
		if n++; n > MaxKafkaTopics {
			return
		}
		led := map[int32]int{}
		for _, p := range t.Partitions {
			if p.Leader >= 0 {
				led[p.Leader]++
			}
		}
		for id, c := range led {
			out.Gauge("kafka.broker.partitions_led", "{partitions}", float64(c),
				map[string]string{"broker": strconv.Itoa(int(id)), "topic": t.Topic}, now)
		}
	}
}
