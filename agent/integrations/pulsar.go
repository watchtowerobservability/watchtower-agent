package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// maxPulsarAgeTopics is how many of the most backlogged topics get an admin stats call per round.
const maxPulsarAgeTopics = 20

// pulsarBacklogAge picks the topics with the largest pulsar_subscription_back_log from the scrape
// and asks the admin API (same host as /metrics, Pulsar 2.11+) for each subscription's earliest
// publish time in its backlog: pulsar.subscription.backlog_age is how old the oldest unconsumed
// message is, and pulsar.subscription.last_ack_age how long since the subscription last acked.
func pulsarBacklogAge(ctx context.Context, c *ExporterConfig, fams map[string]*dto.MetricFamily, out sink.Sink, now time.Time) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return
	}
	base := u.Scheme + "://" + u.Host
	for _, topic := range pulsarBackloggedTopics(fams[`pulsar_subscription_back_log`], maxPulsarAgeTopics) {
		b, err := pulsarGet(ctx, c, base+"/admin/v2/"+pulsarTopicPath(topic)+"/stats?getEarliestTimeInBacklog=true")
		if err != nil {
			continue // older broker, missing permission, topic gone
		}
		_ = EmitPulsarTopicStats(out, topic, b, now)
	}
}

// pulsarBackloggedTopics returns up to n distinct topics, largest subscription backlog first.
func pulsarBackloggedTopics(f *dto.MetricFamily, n int) []string {
	if f == nil {
		return nil
	}
	worst := map[string]float64{}
	for _, m := range f.GetMetric() {
		v := m.GetGauge().GetValue()
		if m.GetUntyped() != nil {
			v = m.GetUntyped().GetValue()
		}
		for _, l := range m.GetLabel() {
			if l.GetName() == "topic" && v > 0 && v > worst[l.GetValue()] {
				worst[l.GetValue()] = v
			}
		}
	}
	ts := make([]string, 0, len(worst))
	for t := range worst {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool {
		if worst[ts[i]] != worst[ts[j]] {
			return worst[ts[i]] > worst[ts[j]]
		}
		return ts[i] < ts[j]
	})
	return ts[:min(n, len(ts))]
}

// pulsarTopicPath turns persistent://tenant/ns/topic into persistent/tenant/ns/topic (each part escaped).
func pulsarTopicPath(topic string) string {
	scheme, rest, ok := strings.Cut(topic, "://")
	if !ok {
		scheme, rest = "persistent", topic
	}
	parts := strings.Split(rest, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return url.PathEscape(scheme) + "/" + strings.Join(parts, "/")
}

func pulsarGet(ctx context.Context, c *ExporterConfig, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	authorize(req, exporterSpec{}, c)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pulsar admin: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// EmitPulsarTopicStats parses one topic's admin stats.
func EmitPulsarTopicStats(out sink.Sink, topic string, body []byte, now time.Time) error {
	var st struct {
		Subscriptions map[string]struct {
			Backlog   float64 `json:"msgBacklog"`
			Earliest  int64   `json:"earliestMsgPublishTimeInBacklog"`
			LastAcked int64   `json:"lastAckedTimestamp"`
			Blocked   bool    `json:"blockedSubscriptionOnUnackedMsgs"`
			Unacked   float64 `json:"unackedMessages"`
			Type      string  `json:"type"`
			Consumers []any   `json:"consumers"`
		} `json:"subscriptions"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("pulsar: not topic stats: %w", err)
	}
	for name, s := range st.Subscriptions {
		a := map[string]string{"topic": topic, "subscription": name}
		out.Gauge("pulsar.subscription.backlog", "{messages}", s.Backlog, a, now)
		out.Gauge("pulsar.subscription.unacked", "{messages}", s.Unacked, a, now)
		if s.Backlog > 0 && s.Earliest > 0 {
			out.Gauge("pulsar.subscription.backlog_age", "s", ageSeconds(now, time.UnixMilli(s.Earliest)), a, now)
		} else if s.Backlog == 0 {
			out.Gauge("pulsar.subscription.backlog_age", "s", 0, a, now)
		}
		if s.Backlog > 0 && s.LastAcked > 0 {
			out.Gauge("pulsar.subscription.last_ack_age", "s", ageSeconds(now, time.UnixMilli(s.LastAcked)), a, now)
		}
		out.Gauge("pulsar.subscription.consumers", "{consumers}", float64(len(s.Consumers)), a, now)
		out.Gauge("pulsar.subscription.blocked_on_unacked", "1", b2f(s.Blocked), a, now)
	}
	return nil
}
