package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// NATS reads the monitoring endpoints /varz and /jsz (with per-account stream and consumer
// detail, so JetStream streams, KV buckets, object stores and their consumers become series).
func NATS(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "nats", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		b, err := getBody(ctx, *c, c.URL+"/varz")
		if err != nil {
			return err
		}
		if err := EmitNATSVarz(out, b, now); err != nil {
			return err
		}
		if b, err := getBody(ctx, *c, c.URL+"/jsz?accounts=true&streams=true&consumers=true"); err == nil { // JetStream may be off
			_ = EmitNATSJsz(out, b, now)
		}
		return nil
	})
}

// EmitNATSVarz parses /varz.
func EmitNATSVarz(out sink.Sink, body []byte, now time.Time) error {
	var v struct {
		Connections   float64 `json:"connections"`
		Subscriptions float64 `json:"subscriptions"`
		SlowConsumers float64 `json:"slow_consumers"`
		InMsgs        float64 `json:"in_msgs"`
		OutMsgs       float64 `json:"out_msgs"`
		InBytes       float64 `json:"in_bytes"`
		OutBytes      float64 `json:"out_bytes"`
		Mem           float64 `json:"mem"`
		CPU           float64 `json:"cpu"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("nats: not /varz: %w", err)
	}
	out.Gauge("nats.connections", "{connections}", v.Connections, nil, now)
	out.Gauge("nats.subscriptions", "{subscriptions}", v.Subscriptions, nil, now)
	out.Gauge("nats.memory", "By", v.Mem, nil, now)
	out.Gauge("nats.cpu", "%", v.CPU, nil, now)
	out.Sum("nats.slow_consumers", "{consumers}", v.SlowConsumers, nil, now)
	out.Sum("nats.messages.in", "{messages}", v.InMsgs, nil, now)
	out.Sum("nats.messages.out", "{messages}", v.OutMsgs, nil, now)
	out.Sum("nats.bytes.in", "By", v.InBytes, nil, now)
	out.Sum("nats.bytes.out", "By", v.OutBytes, nil, now)
	return nil
}

// JetStream caps: streams (KV and object buckets included) and consumers with their own series.
const maxNATSStreams, maxNATSConsumers = 200, 500

type natsSeq struct {
	StreamSeq   float64   `json:"stream_seq"`
	ConsumerSeq float64   `json:"consumer_seq"`
	LastActive  time.Time `json:"last_active"`
}

type natsStream struct {
	Name    string `json:"name"`
	Cluster struct {
		Leader   string `json:"leader"`
		Replicas []struct {
			Current bool `json:"current"`
			Offline bool `json:"offline"`
		} `json:"replicas"`
	} `json:"cluster"`
	State struct {
		Messages  float64 `json:"messages"`
		Bytes     float64 `json:"bytes"`
		Consumers float64 `json:"consumer_count"`
		Subjects  float64 `json:"num_subjects"`
	} `json:"state"`
	Consumers []struct {
		Name        string  `json:"name"`
		Pending     float64 `json:"num_pending"`
		AckPending  float64 `json:"num_ack_pending"`
		Redelivered float64 `json:"num_redelivered"`
		Waiting     float64 `json:"num_waiting"`
		Delivered   natsSeq `json:"delivered"`
		AckFloor    natsSeq `json:"ack_floor"`
	} `json:"consumer_detail"`
}

// EmitNATSJsz parses /jsz: server totals and, when account detail is present, per stream and
// consumer. KV_<b> and OBJ_<b> streams are labelled kind=kv/object with bucket=<b>.
func EmitNATSJsz(out sink.Sink, body []byte, now time.Time) error {
	var v struct {
		Streams   float64 `json:"streams"`
		Consumers float64 `json:"consumers"`
		Messages  float64 `json:"messages"`
		Bytes     float64 `json:"bytes"`
		Memory    float64 `json:"memory"`
		Storage   float64 `json:"storage"`
		Config    struct {
			MaxMemory  float64 `json:"max_memory"`
			MaxStorage float64 `json:"max_storage"`
		} `json:"config"`
		API struct {
			Total  float64 `json:"total"`
			Errors float64 `json:"errors"`
		} `json:"api"`
		Accounts []struct {
			Name    string       `json:"name"`
			Streams []natsStream `json:"stream_detail"`
		} `json:"account_details"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	out.Gauge("nats.jetstream.streams", "{streams}", v.Streams, nil, now)
	out.Gauge("nats.jetstream.consumers", "{consumers}", v.Consumers, nil, now)
	out.Gauge("nats.jetstream.messages", "{messages}", v.Messages, nil, now)
	out.Gauge("nats.jetstream.bytes", "By", v.Bytes, nil, now)
	out.Gauge("nats.jetstream.memory.used", "By", v.Memory, nil, now)
	out.Gauge("nats.jetstream.storage.used", "By", v.Storage, nil, now)
	out.Gauge("nats.jetstream.memory.limit", "By", v.Config.MaxMemory, nil, now)
	out.Gauge("nats.jetstream.storage.limit", "By", v.Config.MaxStorage, nil, now)
	out.Sum("nats.jetstream.api.requests", "{requests}", v.API.Total, nil, now)
	out.Sum("nats.jetstream.api.errors", "{requests}", v.API.Errors, nil, now)
	ns, nc := 0, 0
	for _, acc := range v.Accounts {
		for _, s := range acc.Streams {
			if ns++; ns > maxNATSStreams {
				return nil
			}
			kind, bucket := "stream", ""
			if b, ok := strings.CutPrefix(s.Name, "KV_"); ok {
				kind, bucket = "kv", b
			} else if b, ok := strings.CutPrefix(s.Name, "OBJ_"); ok {
				kind, bucket = "object", b
			}
			a := map[string]string{"account": acc.Name, "stream": s.Name}
			lagging := 0
			for _, r := range s.Cluster.Replicas {
				if !r.Current || r.Offline {
					lagging++
				}
			}
			out.Gauge("nats.jetstream.stream.messages", "{messages}", s.State.Messages, a, now)
			out.Gauge("nats.jetstream.stream.bytes", "By", s.State.Bytes, a, now)
			out.Gauge("nats.jetstream.stream.consumers", "{consumers}", s.State.Consumers, a, now)
			out.Gauge("nats.jetstream.stream.subjects", "{subjects}", s.State.Subjects, a, now)
			out.Gauge("nats.jetstream.stream.replicas_lagging", "{replicas}", float64(lagging), a, now)
			out.Gauge("nats.jetstream.stream.info", "1", 1, map[string]string{"account": acc.Name, "stream": s.Name,
				"kind": kind, "bucket": bucket, "leader": s.Cluster.Leader}, now)
			for _, c := range s.Consumers {
				if nc++; nc > maxNATSConsumers {
					break
				}
				ca := map[string]string{"account": acc.Name, "stream": s.Name, "consumer": c.Name}
				out.Gauge("nats.jetstream.consumer.pending", "{messages}", c.Pending, ca, now)
				out.Gauge("nats.jetstream.consumer.ack_pending", "{messages}", c.AckPending, ca, now)
				out.Gauge("nats.jetstream.consumer.redelivered", "{messages}", c.Redelivered, ca, now)
				out.Gauge("nats.jetstream.consumer.waiting", "{requests}", c.Waiting, ca, now)
				out.Sum("nats.jetstream.consumer.delivered", "{messages}", c.Delivered.ConsumerSeq, ca, now)
				// The ack floor stops moving while the oldest message is unacknowledged: its age is the lag in time.
				if (c.Pending > 0 || c.AckPending > 0) && !c.AckFloor.LastActive.IsZero() {
					out.Gauge("nats.jetstream.consumer.ack_floor_age", "s", max(0, now.Sub(c.AckFloor.LastActive).Seconds()), ca, now)
				}
			}
		}
	}
	return nil
}
