package sink

import (
	"strings"
	"time"
)

// The Queues area (APM-009) reads one metric contract whatever the broker: messaging.queue.depth
// {queue, framework, state}, messaging.queue.oldest_age_seconds and messaging.consumer.lag_seconds.
// QueueContract wraps a Sink and, for each broker metric in queueMaps, also writes that contract
// series, so every collector (RabbitMQ, ActiveMQ and Artemis, NATS JetStream, Pulsar, Kafka, Redis
// streams, SQS, Kinesis, Service Bus, Pub/Sub) feeds the data-streams view without changing its own
// native series. A point without a queue name is skipped.
const (
	QueueDepth = "messaging.queue.depth"
	QueueAge   = "messaging.queue.oldest_age_seconds"
	QueueLag   = "messaging.consumer.lag_seconds"
)

type queueMap struct {
	metric    string // contract metric
	framework string
	state     string   // depth state ("" for age and lag)
	queue     []string // attribute keys tried in order for the destination name
	keep      []string // attributes copied so series of one queue stay apart (vhost, group)
	scale     float64  // multiplies the value (milliseconds to seconds)
}

var (
	rmqKeep = []string{"vhost"}
	grpKeep = []string{"group"}
)

var queueMaps = map[string]queueMap{
	"rabbitmq.queue.ready":                  {QueueDepth, "rabbitmq", "ready", []string{"queue"}, rmqKeep, 1},
	"rabbitmq.queue.unacknowledged":         {QueueDepth, "rabbitmq", "unacked", []string{"queue"}, rmqKeep, 1},
	"rabbitmq.queue.oldest_message_age":     {QueueAge, "rabbitmq", "", []string{"queue"}, rmqKeep, 1},
	"activemq.queue.size":                   {QueueDepth, "activemq", "ready", []string{"queue"}, []string{"broker"}, 1},
	"activemq.queue.in_flight":              {QueueDepth, "activemq", "unacked", []string{"queue"}, []string{"broker"}, 1},
	"artemis.queue.messages":                {QueueDepth, "artemis", "ready", []string{"queue"}, []string{"broker", "address"}, 1},
	"artemis.queue.delivering":              {QueueDepth, "artemis", "unacked", []string{"queue"}, []string{"broker", "address"}, 1},
	"artemis.queue.oldest_message_age":      {QueueAge, "artemis", "", []string{"queue"}, []string{"broker", "address"}, 1},
	"nats.jetstream.consumer.pending":       {QueueDepth, "nats", "ready", []string{"stream"}, []string{"account", "consumer"}, 1},
	"nats.jetstream.consumer.ack_pending":   {QueueDepth, "nats", "unacked", []string{"stream"}, []string{"account", "consumer"}, 1},
	"pulsar.subscription.backlog":           {QueueDepth, "pulsar", "ready", []string{"topic"}, []string{"subscription"}, 1},
	"pulsar.subscription.unacked":           {QueueDepth, "pulsar", "unacked", []string{"topic"}, []string{"subscription"}, 1},
	"pulsar.subscription.backlog_age":       {QueueAge, "pulsar", "", []string{"topic"}, []string{"subscription"}, 1},
	"kafka.consumer_group.lag_sum":          {QueueDepth, "kafka", "ready", []string{"topic"}, grpKeep, 1},
	"kafka.consumer_group.lag_time":         {QueueLag, "kafka", "", []string{"topic"}, grpKeep, 1},
	"redis.stream.group.lag":                {QueueDepth, "redis", "ready", []string{"stream"}, grpKeep, 1},
	"redis.stream.group.pending":            {QueueDepth, "redis", "unacked", []string{"stream"}, grpKeep, 1},
	"redis.stream.group.oldest_pending_age": {QueueAge, "redis", "", []string{"stream"}, grpKeep, 1},
	"redis.stream.group.lag_time":           {QueueLag, "redis", "", []string{"stream"}, grpKeep, 1},

	"amazonaws.com/AWS/SQS/ApproximateNumberOfMessagesVisible":     {QueueDepth, "sqs", "ready", []string{"aws.dim.QueueName"}, nil, 1},
	"amazonaws.com/AWS/SQS/ApproximateNumberOfMessagesNotVisible":  {QueueDepth, "sqs", "unacked", []string{"aws.dim.QueueName"}, nil, 1},
	"amazonaws.com/AWS/SQS/ApproximateAgeOfOldestMessage":          {QueueAge, "sqs", "", []string{"aws.dim.QueueName"}, nil, 1},
	"amazonaws.com/AWS/Kinesis/GetRecords.IteratorAgeMilliseconds": {QueueLag, "kinesis", "", []string{"aws.dim.StreamName"}, nil, 0.001},

	"cloud.azure.microsoft.servicebus.namespaces.activemessages":       {QueueDepth, "servicebus", "ready", []string{"azure.entity", ResourcePrefix + "cloud.resource_id"}, nil, 1},
	"cloud.azure.microsoft.servicebus.namespaces.deadletteredmessages": {QueueDepth, "servicebus", "dead", []string{"azure.entity", ResourcePrefix + "cloud.resource_id"}, nil, 1},

	"cloud.gcp.pubsub.subscription.num_undelivered_messages":   {QueueDepth, "pubsub", "ready", []string{"gcp.resource.subscription_id"}, nil, 1},
	"cloud.gcp.pubsub.subscription.oldest_unacked_message_age": {QueueAge, "pubsub", "", []string{"gcp.resource.subscription_id"}, nil, 1},
	"cloud.gcp.pubsub.subscription.dead_letter_message_count":  {QueueDepth, "pubsub", "dead", []string{"gcp.resource.subscription_id"}, nil, 1},
}

type queueSink struct{ Sink }

// QueueContract returns out with the Queues-area series added next to the broker's own.
func QueueContract(out Sink) Sink {
	if _, ok := out.(queueSink); ok || out == nil {
		return out
	}
	return queueSink{out}
}

// Gauge forwards the point, then writes its contract twin when the metric is mapped.
func (q queueSink) Gauge(name, unit string, v float64, attrs map[string]string, at time.Time) {
	q.Sink.Gauge(name, unit, v, attrs, at)
	m, ok := queueMaps[name]
	if !ok {
		return
	}
	dest := ""
	for _, k := range m.queue {
		if dest = attrs[k]; dest != "" {
			break
		}
	}
	if dest == "" || dest == "*" {
		return
	}
	a := map[string]string{"queue": dest, "framework": m.framework}
	if m.state != "" {
		a["state"] = m.state
	}
	for _, k := range m.keep {
		if attrs[k] != "" {
			a[k] = attrs[k]
		}
	}
	for k, val := range attrs { // resource identity (account, region) stays on the twin
		if strings.HasPrefix(k, ResourcePrefix) {
			a[k] = val
		}
	}
	u := "{messages}"
	if m.metric != QueueDepth {
		u = "s"
	}
	q.Sink.Gauge(m.metric, u, v*m.scale, a, at)
}
