package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// NATS reads the monitoring endpoints /varz and /jsz.
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
		if b, err := getBody(ctx, *c, c.URL+"/jsz"); err == nil { // JetStream may be off
			_ = EmitNATSJsz(out, b, now)
		}
		return nil
	})
}

// EmitNATSVarz parses /varz.
func EmitNATSVarz(out sink.Sink, body []byte, now time.Time) error {
	var v struct {
		Connections   float64 `json:"connections"`
		SlowConsumers float64 `json:"slow_consumers"`
		InMsgs        float64 `json:"in_msgs"`
		OutMsgs       float64 `json:"out_msgs"`
		Mem           float64 `json:"mem"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("nats: not /varz: %w", err)
	}
	out.Gauge("nats.connections", "{connections}", v.Connections, nil, now)
	out.Gauge("nats.memory", "By", v.Mem, nil, now)
	out.Sum("nats.slow_consumers", "{consumers}", v.SlowConsumers, nil, now)
	out.Sum("nats.messages.in", "{messages}", v.InMsgs, nil, now)
	out.Sum("nats.messages.out", "{messages}", v.OutMsgs, nil, now)
	return nil
}

// EmitNATSJsz parses /jsz.
func EmitNATSJsz(out sink.Sink, body []byte, now time.Time) error {
	var v struct {
		Streams   float64 `json:"streams"`
		Consumers float64 `json:"consumers"`
		Messages  float64 `json:"messages"`
		Bytes     float64 `json:"bytes"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	out.Gauge("nats.jetstream.streams", "{streams}", v.Streams, nil, now)
	out.Gauge("nats.jetstream.consumers", "{consumers}", v.Consumers, nil, now)
	out.Gauge("nats.jetstream.messages", "{messages}", v.Messages, nil, now)
	out.Gauge("nats.jetstream.bytes", "By", v.Bytes, nil, now)
	return nil
}
