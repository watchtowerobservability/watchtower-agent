package integrations

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// KafkaConfig is the kafka module's config. Brokers and credentials are local-file only.
type KafkaConfig struct {
	Base
	Brokers      []string `json:"brokers"`
	SASLUser     string   `json:"sasl_user"`
	SASLPassword string   `json:"sasl_password"`
	TLS          bool     `json:"tls"`
	// Groups limits lag to these consumer groups (default: all). Either way at most
	// MaxKafkaGroups groups are described, the first by name.
	Groups []string `json:"groups"`
}

func (c *KafkaConfig) check() error {
	if len(c.Brokers) == 0 {
		return errors.New("kafka: brokers are required (in the agent's own config file)")
	}
	return nil
}

// Series caps. What a cap leaves out is counted in `wt_agent_kafka_dropped_total{what}`.
const (
	MaxKafkaGroups                              = 200
	MaxKafkaTopics                              = 500 // topics with partition health, and lag_sum topics per group
	maxLagSeries                                = 2000
	maxLagSumSeries                             = 5000
	droppedMetric                               = "wt_agent_kafka_dropped_total"
	droppedGroups, droppedTopics, droppedSeries = "groups", "topics", "series"
)

// KafkaState carries what a collector keeps between rounds (the cumulative drop counters).
type KafkaState struct{ dropped map[string]float64 }

func (s *KafkaState) drop(what string, n int) {
	if s.dropped == nil {
		s.dropped = map[string]float64{}
	}
	s.dropped[what] += float64(n)
}

// Kafka reports consumer lag per group and partition, and under-replicated and offline
// partitions per topic, through the Kafka admin API.
func Kafka(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &KafkaConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.SASLUser != "" && !c.TLS {
		slog.Warn("kafka: SASL PLAIN without tls sends the password in clear text")
	}
	opts := []kgo.Opt{kgo.SeedBrokers(c.Brokers...), kgo.ClientID("wt-agent")}
	if c.TLS {
		opts = append(opts, kgo.DialTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	if c.SASLUser != "" {
		opts = append(opts, kgo.SASL(plain.Auth{User: c.SASLUser, Pass: c.SASLPassword}.AsMechanism()))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return err
	}
	defer cl.Close()
	adm := kadm.NewClient(cl)
	st := &KafkaState{}
	return Loop(ctx, "kafka", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		return CollectKafka(ctx, adm, c.Groups, st, out, now)
	})
}

// CollectKafka runs one round. st may be nil.
func CollectKafka(ctx context.Context, adm *kadm.Client, groups []string, st *KafkaState, out sink.Sink, now time.Time) error {
	if st == nil {
		st = &KafkaState{}
	}
	topics, err := adm.ListTopics(ctx)
	if err != nil {
		return err
	}
	type health struct {
		topic          string
		under, offline int
	}
	var hs []health
	for _, t := range topics.Sorted() {
		under, offline := PartitionHealth(t.Partitions)
		hs = append(hs, health{t.Topic, under, offline})
	}
	// Unhealthy topics first so a cap never hides a problem; then by name.
	sort.SliceStable(hs, func(i, j int) bool {
		bi, bj := hs[i].under+hs[i].offline > 0, hs[j].under+hs[j].offline > 0
		return bi && !bj
	})
	if len(hs) > MaxKafkaTopics {
		st.drop(droppedTopics, len(hs)-MaxKafkaTopics)
		hs = hs[:MaxKafkaTopics]
	}
	for _, h := range hs {
		a := map[string]string{"topic": h.topic}
		out.Gauge("kafka.partitions.under_replicated", "{partitions}", float64(h.under), a, now)
		out.Gauge("kafka.partitions.offline", "{partitions}", float64(h.offline), a, now)
	}

	if len(groups) == 0 {
		listed, err := adm.ListGroups(ctx)
		if err != nil {
			return err
		}
		groups = listed.Groups()
	} else {
		groups = append([]string(nil), groups...)
		sort.Strings(groups)
	}
	if len(groups) > MaxKafkaGroups {
		st.drop(droppedGroups, len(groups)-MaxKafkaGroups)
		groups = groups[:MaxKafkaGroups]
	}
	if len(groups) > 0 {
		lags, err := adm.Lag(ctx, groups...)
		if err != nil {
			return err
		}
		emitLag(out, lags, st, now)
	}
	for what, n := range st.dropped {
		out.Sum(droppedMetric, "1", n, map[string]string{"what": what}, now)
	}
	return nil
}

type lagPoint struct {
	group, topic, partition string
	lag                     float64
}

// emitLag writes the worst lags first: per partition (at most maxLagSeries) and per group and
// topic (at most MaxKafkaTopics topics per group and maxLagSumSeries overall).
func emitLag(out sink.Sink, lags kadm.DescribedGroupLags, st *KafkaState, now time.Time) {
	var parts, sums []lagPoint
	for _, g := range lags.Sorted() {
		if g.Error() != nil {
			continue
		}
		var perGroup []lagPoint
		for topic, ps := range g.Lag {
			sum := 0.0
			for p, l := range ps {
				v := float64(max(l.Lag, 0))
				sum += v
				parts = append(parts, lagPoint{g.Group, topic, strconv.Itoa(int(p)), v})
			}
			perGroup = append(perGroup, lagPoint{group: g.Group, topic: topic, lag: sum})
		}
		sortLag(perGroup)
		if len(perGroup) > MaxKafkaTopics {
			st.drop(droppedTopics, len(perGroup)-MaxKafkaTopics)
			perGroup = perGroup[:MaxKafkaTopics]
		}
		sums = append(sums, perGroup...)
	}
	sortLag(parts)
	if len(parts) > maxLagSeries {
		st.drop(droppedSeries, len(parts)-maxLagSeries)
		parts = parts[:maxLagSeries]
	}
	sortLag(sums)
	if len(sums) > maxLagSumSeries {
		st.drop(droppedSeries, len(sums)-maxLagSumSeries)
		sums = sums[:maxLagSumSeries]
	}
	for _, p := range parts {
		out.Gauge("kafka.consumer_group.lag", "{messages}", p.lag,
			map[string]string{"group": p.group, "topic": p.topic, "partition": p.partition}, now)
	}
	for _, p := range sums {
		out.Gauge("kafka.consumer_group.lag_sum", "{messages}", p.lag,
			map[string]string{"group": p.group, "topic": p.topic}, now)
	}
}

func sortLag(ps []lagPoint) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].lag != ps[j].lag {
			return ps[i].lag > ps[j].lag
		}
		if ps[i].group != ps[j].group {
			return ps[i].group < ps[j].group
		}
		if ps[i].topic != ps[j].topic {
			return ps[i].topic < ps[j].topic
		}
		return ps[i].partition < ps[j].partition
	})
}

// PartitionHealth counts partitions whose in-sync replicas are fewer than their replicas, and
// partitions without a leader.
func PartitionHealth(ps kadm.PartitionDetails) (under, offline int) {
	for _, p := range ps {
		if p.Leader < 0 {
			offline++
		} else if len(p.ISR) < len(p.Replicas) {
			under++
		}
	}
	return under, offline
}
