package integrations

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Artemis reads an ActiveMQ Artemis broker through its Jolokia endpoint (the console's
// /console/jolokia): broker memory and disk use, replication, connections, and per queue depth,
// in-delivery, throughput, expired and killed (dead-lettered) messages and the age of the first
// message.
func Artemis(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runJolokia(ctx, "artemis", artemisReads, raw, out, emitArtemis)
}

var artemisReads = []MBeanRead{{
	MBean: "org.apache.activemq.artemis:broker=*",
	Attributes: []string{"AddressMemoryUsage", "AddressMemoryUsagePercentage", "DiskStoreUsage", "MaxDiskUsage",
		"ConnectionCount", "TotalConnectionCount", "TotalMessageCount", "Active", "ReplicaSync", "Backup"},
}, {
	MBean: "org.apache.activemq.artemis:broker=*,component=addresses,address=*,subcomponent=queues,routing-type=*,queue=*",
	Attributes: []string{"MessageCount", "ConsumerCount", "DeliveringCount", "ScheduledCount", "MessagesAdded",
		"MessagesAcknowledged", "MessagesExpired", "MessagesKilled", "FirstMessageAge", "Paused"},
}}

type jmxMetric struct {
	name, unit string
	sum        bool
	scale      float64 // multiplier; 0 means 1
}

var artemisBroker = map[string]jmxMetric{
	"AddressMemoryUsage":           {"artemis.broker.address_memory.used", "By", false, 0},
	"AddressMemoryUsagePercentage": {"artemis.broker.address_memory.percent", "%", false, 0},
	"DiskStoreUsage":               {"artemis.broker.disk.usage", "1", false, 0}, // fraction of the disk
	"MaxDiskUsage":                 {"artemis.broker.disk.max_usage", "%", false, 0},
	"ConnectionCount":              {"artemis.broker.connections", "{connections}", false, 0},
	"TotalConnectionCount":         {"artemis.broker.connections.created", "{connections}", true, 0},
	"TotalMessageCount":            {"artemis.broker.messages", "{messages}", false, 0},
	"Active":                       {"artemis.broker.active", "1", false, 0},
	"ReplicaSync":                  {"artemis.broker.replica_sync", "1", false, 0},
	"Backup":                       {"artemis.broker.backup", "1", false, 0},
}

var artemisQueue = map[string]jmxMetric{
	"MessageCount":         {"artemis.queue.messages", "{messages}", false, 0},
	"ConsumerCount":        {"artemis.queue.consumers", "{consumers}", false, 0},
	"DeliveringCount":      {"artemis.queue.delivering", "{messages}", false, 0},
	"ScheduledCount":       {"artemis.queue.scheduled", "{messages}", false, 0},
	"MessagesAdded":        {"artemis.queue.messages.added", "{messages}", true, 0},
	"MessagesAcknowledged": {"artemis.queue.messages.acknowledged", "{messages}", true, 0},
	"MessagesExpired":      {"artemis.queue.messages.expired", "{messages}", true, 0},
	"MessagesKilled":       {"artemis.queue.messages.killed", "{messages}", true, 0},
	"FirstMessageAge":      {"artemis.queue.oldest_message_age", "s", false, 0.001}, // ms; null when empty
	"Paused":               {"artemis.queue.paused", "1", false, 0},
}

func emitJMXMetric(out sink.Sink, m jmxMetric, v any, a map[string]string, now time.Time) {
	f, ok := v.(float64)
	if b, isBool := v.(bool); isBool {
		f, ok = b2f(b), true
	}
	if !ok {
		return
	}
	if m.scale != 0 {
		f *= m.scale
	}
	if m.sum {
		out.Sum(m.name, m.unit, f, a, now)
	} else {
		out.Gauge(m.name, m.unit, f, a, now)
	}
}

// emitArtemis writes the brokers and the 200 deepest queues.
func emitArtemis(out sink.Sink, rs []jolokiaResp, now time.Time) {
	type queue struct {
		attrs map[string]string
		vals  map[string]any
		depth float64
	}
	var qs []queue
	for _, r := range rs {
		perMBean(r, func(mbean string, attrs map[string]any) {
			p := mbeanProps(mbean)
			if p["queue"] == "" {
				for k, v := range attrs {
					if m, ok := artemisBroker[k]; ok {
						emitJMXMetric(out, m, v, map[string]string{"broker": p["broker"]}, now)
					}
				}
				return
			}
			d, _ := attrs["MessageCount"].(float64)
			qs = append(qs, queue{map[string]string{"broker": p["broker"], "address": p["address"], "queue": p["queue"],
				"routing_type": p["routing-type"]}, attrs, d})
		})
	}
	sort.SliceStable(qs, func(i, j int) bool { return qs[i].depth > qs[j].depth })
	for _, q := range qs[:min(len(qs), 200)] {
		for k, v := range q.vals {
			if m, ok := artemisQueue[k]; ok {
				emitJMXMetric(out, m, v, q.attrs, now)
			}
		}
	}
}
