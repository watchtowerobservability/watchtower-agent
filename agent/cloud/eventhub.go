package cloud

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// EventHubConfig reads Azure diagnostic logs and metrics from an Event Hubs namespace through its
// Kafka-compatible endpoint (port 9093, SASL PLAIN, user "$ConnectionString").
type EventHubConfig struct {
	Enabled *bool `json:"enabled"`
	// ConnectionString or ConnectionStringEnv holds the namespace connection string. It is a
	// secret: it is never logged, exported or placed in an error.
	ConnectionString    string   `json:"connection_string"`
	ConnectionStringEnv string   `json:"connection_string_env"`
	Brokers             []string `json:"brokers"` // default <namespace>.servicebus.windows.net:9093
	Topics              []string `json:"topics"`  // event hub names
	Group               string   `json:"group"`   // consumer group, default wt-agent
	// Plaintext disables TLS and SASL; for a local Kafka stand-in only.
	Plaintext bool `json:"plaintext"`
	// StartAtEarliest makes a group with no committed offset read from the start of retention
	// instead of from now. Off by default: days of history would flood the export buffer.
	StartAtEarliest bool `json:"start_at_earliest"`
}

const maxHubRecord = 4 << 20

func (c EventHubConfig) secret() string {
	if c.ConnectionString != "" {
		return c.ConnectionString
	}
	if c.ConnectionStringEnv != "" {
		return os.Getenv(c.ConnectionStringEnv)
	}
	return ""
}

// brokersOf returns the configured brokers or the one named by the connection string's Endpoint.
func brokersOf(c EventHubConfig, conn string) []string {
	if len(c.Brokers) > 0 {
		return c.Brokers
	}
	for _, part := range strings.Split(conn, ";") {
		if v, ok := strings.CutPrefix(part, "Endpoint="); ok {
			if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
				return []string{u.Hostname() + ":9093"}
			}
		}
	}
	return nil
}

// RunEventHub consumes until ctx ends.
func RunEventHub(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c EventHubConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled || len(c.Topics) == 0 {
		<-ctx.Done()
		return nil
	}
	conn := c.secret()
	brokers := brokersOf(c, conn)
	if len(brokers) == 0 || conn == "" && !c.Plaintext {
		return errors.New("azure eventhub: need a connection string (or brokers with plaintext)")
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...), kgo.ConsumeTopics(c.Topics...),
		kgo.ConsumerGroup(firstNonEmpty(c.Group, "wt-agent")),
		// A group with no committed offset starts at the latest record, not the earliest: a hub
		// keeps days of history that would flood the export buffer. Offsets are committed by hand,
		// only after the records were exported (at-least-once).
		kgo.ConsumeResetOffset(resetOffset(c)), kgo.DisableAutoCommit(),
		kgo.DialTimeout(10 * time.Second), kgo.RequestRetries(3), kgo.RetryTimeout(30 * time.Second),
		kgo.FetchMaxBytes(4 << 20), kgo.FetchMaxPartitionBytes(maxHubRecord),
	}
	if !c.Plaintext {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}),
			kgo.SASL(plain.Auth{User: "$ConnectionString", Pass: conn}.AsMechanism()))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return host.Redact(err, conn)
	}
	defer cl.Close()
	d, _ := out.(sink.Delivering) // before Hoist wraps it; nil for a sink that cannot confirm
	return consume(ctx, cl, c.Topics, sink.Hoist(out), d, conn)
}

const (
	highWater    = 4 << 20 // buffered bytes above which fetching pauses
	retryBackoff = 5 * time.Second
)

// consume polls, processes, then flushes and commits. While the export buffer is above the
// high-water mark (or an export fails) it pauses fetching and retries the flush; the offsets of
// records that were not exported stay uncommitted.
func consume(ctx context.Context, cl *kgo.Client, topics []string, out sink.Sink, d sink.Delivering, conn string) error {
	commit := func() {
		if err := cl.CommitUncommittedOffsets(ctx); err != nil && ctx.Err() == nil {
			host.Warn("eventhub commit", host.Redact(err, conn))
		}
	}
	paused := false
	for ctx.Err() == nil {
		if d != nil && d.Buffered() > highWater {
			if !paused {
				cl.PauseFetchTopics(topics...)
				paused = true
			}
			if err := d.Flush(ctx); err != nil {
				host.Warn("eventhub export", host.Redact(err, conn))
				select {
				case <-ctx.Done():
				case <-time.After(retryBackoff):
				}
				continue
			}
			commit()
		}
		if paused {
			cl.ResumeFetchTopics(topics...)
			paused = false
		}
		fs := cl.PollFetches(ctx)
		if fs.IsClientClosed() {
			return nil
		}
		fs.EachError(func(t string, p int32, err error) {
			if ctx.Err() == nil {
				host.Warn("eventhub fetch "+t, host.Redact(fmt.Errorf("partition %d: %w", p, err), conn))
			}
		})
		n := 0
		fs.EachRecord(func(r *kgo.Record) {
			n++
			if len(r.Value) <= maxHubRecord {
				Process(out, r.Value, time.Now())
			}
		})
		if n == 0 {
			continue
		}
		if d == nil {
			commit() // a sink with no delivery confirmation (tests)
		} else if err := d.Flush(ctx); err != nil {
			host.Warn("eventhub export", host.Redact(err, conn)) // offsets stay uncommitted; the pause path retries
		} else {
			commit()
		}
	}
	return nil
}

func resetOffset(c EventHubConfig) kgo.Offset {
	if c.StartAtEarliest {
		return kgo.NewOffset().AtStart()
	}
	return kgo.NewOffset().AtEnd()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type hubRecord struct {
	Time          string          `json:"time"`
	ResourceID    string          `json:"resourceId"`
	Category      string          `json:"category"`
	OperationName string          `json:"operationName"`
	Level         json.RawMessage `json:"level"`
	MetricName    string          `json:"metricName"`
	Average       *float64        `json:"average"`
	Total         *float64        `json:"total"`
	TimeGrain     string          `json:"timeGrain"`
}

var azureLevel = map[string]string{
	"verbose": "DEBUG", "informational": "INFO", "information": "INFO", "warning": "WARN",
	"error": "ERROR", "critical": "ERROR", "5": "DEBUG", "4": "INFO", "3": "WARN", "2": "ERROR", "1": "ERROR",
}

// Process turns one Event Hubs message ({"records": [...]} of diagnostic logs or metrics) into
// samples and log records. Each Azure resource id becomes a cloud entity through the resource.
func Process(out sink.Sink, msg []byte, now time.Time) {
	var env struct {
		Records []json.RawMessage `json:"records"`
	}
	if json.Unmarshal(msg, &env) != nil {
		return
	}
	for _, raw := range env.Records {
		var r hubRecord
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		at := now
		if t, err := time.Parse(time.RFC3339Nano, r.Time); err == nil {
			at = t
		}
		attrs := sink.Res(map[string]string{
			"cloud.provider": "azure", "cloud.resource_id": strings.ToLower(r.ResourceID),
			"host.id": "", "host.name": "",
		})
		if r.ResourceID == "" {
			attrs = map[string]string{"cloud.provider": "azure"}
		}
		if r.MetricName != "" {
			v := r.Average
			if v == nil {
				v = r.Total
			}
			if v != nil {
				attrs["azure.time_grain"] = r.TimeGrain
				out.Gauge("azure.monitor."+r.MetricName, "", *v, attrs, at)
			}
			continue
		}
		attrs["azure.category"], attrs["azure.operation"] = r.Category, r.OperationName
		var lvl string
		_ = json.Unmarshal(r.Level, &lvl)
		if lvl == "" {
			lvl = strings.Trim(string(r.Level), `"`)
		}
		sev, ok := azureLevel[strings.ToLower(lvl)]
		if !ok {
			sev = "INFO"
		}
		out.Log(sev, string(raw), attrs, at)
	}
}
