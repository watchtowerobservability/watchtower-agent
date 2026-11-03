package logs

// Kafka topic log source (CFT-A07, Alloy loki.source.kafka parity): one consumer group reads
// the configured topics; each record value is one log line (a JSON object with `message`/`msg`
// or `log` keeps its other fields as attributes). Offsets are committed after the records are
// handed to the exporter, so delivery is at-least-once.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// KafkaLogs is the consumer's configuration. The SASL password may be a secret reference.
type KafkaLogs struct {
	Brokers []string `json:"brokers"`
	Topics  []string `json:"topics"`
	Group   string   `json:"group"` // default wt-agent-logs
	TLS     bool     `json:"tls"`
	SASL    *struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"sasl_plain"`
}

// RunKafka consumes until ctx ends.
func RunKafka(ctx context.Context, c KafkaLogs, out sink.Sink) error {
	if len(c.Brokers) == 0 || len(c.Topics) == 0 {
		return errors.New("kafka: brokers and topics are required")
	}
	group := c.Group
	if group == "" {
		group = "wt-agent-logs"
	}
	opts := []kgo.Opt{kgo.SeedBrokers(c.Brokers...), kgo.ConsumeTopics(c.Topics...), kgo.ConsumerGroup(group),
		kgo.DisableAutoCommit(), kgo.FetchMaxBytes(16 << 20)}
	if c.TLS {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	if c.SASL != nil {
		opts = append(opts, kgo.SASL(plain.Auth{User: c.SASL.Username, Pass: c.SASL.Password}.AsMechanism()))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return errors.New("kafka: client")
	}
	defer cl.Close()
	for {
		fs := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if errs := fs.Errors(); len(errs) > 0 {
			return fmt.Errorf("kafka: fetch from %s: %w", errs[0].Topic, errs[0].Err)
		}
		fs.EachRecord(func(r *kgo.Record) { KafkaRecord(out, r) })
		if err := cl.CommitUncommittedOffsets(ctx); err != nil && ctx.Err() == nil {
			return fmt.Errorf("kafka: commit: %w", err)
		}
	}
}

// KafkaRecord writes one record as a log line.
func KafkaRecord(out sink.Sink, r *kgo.Record) {
	attrs := map[string]string{"messaging.system": "kafka", "messaging.destination.name": r.Topic,
		"messaging.kafka.partition": fmt.Sprint(r.Partition)}
	body := string(r.Value)
	var m map[string]any
	if json.Unmarshal(r.Value, &m) == nil {
		for _, k := range []string{"message", "msg", "log"} {
			if s, ok := m[k].(string); ok {
				body = s
				delete(m, k)
				for k2, v := range m {
					if s2, ok := v.(string); ok && len(attrs) < 64 {
						attrs[k2] = s2
					}
				}
				break
			}
		}
	}
	out.Log(Severity(body), body, attrs, r.Timestamp)
}
