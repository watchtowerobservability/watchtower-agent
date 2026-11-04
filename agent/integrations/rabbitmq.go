package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// HTTPConfig is shared by the modules that read a product's HTTP status or management API.
// URL and credentials are local-file only.
type HTTPConfig struct {
	Base
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *HTTPConfig) check() error {
	if !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
		return errors.New("url (http or https) is required (in the agent's own config file)")
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return nil
}

const maxBody = 8 << 20

var httpClient = netguard.Guarded("agent", 15*time.Second)

// getBody fetches url with optional basic auth and a bounded body.
func getBody(ctx context.Context, c HTTPConfig, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

// RabbitMQ reads the management API every round: the 200 deepest queues (depth, rates,
// consumer capacity, oldest message age, quorum members, dead-letter target), the cluster
// overview (message rates, unroutable drops, connection and channel churn) and, when the
// management user may read them, nodes (memory and disk alarms, partitions, descriptors),
// consumers (prefetch and ack mode per queue), streams, shovels and federation links.
func RabbitMQ(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "rabbitmq", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		return collectRabbit(ctx, *c, out, now)
	})
}

const rabbitQueueColumns = "name,vhost,type,state,messages,messages_ready,messages_unacknowledged,consumers," +
	"consumer_capacity,consumer_utilisation,memory,head_message_timestamp,arguments,effective_policy_definition," +
	"leader,members,online,message_stats.publish,message_stats.deliver_get,message_stats.ack,message_stats.redeliver"

// collectRabbit fails the round only when queues or the overview cannot be read; the other
// endpoints need the monitoring tag or a plugin (shovel, federation, stream) and are optional.
func collectRabbit(ctx context.Context, c HTTPConfig, out sink.Sink, now time.Time) error {
	b, err := getBody(ctx, c, c.URL+"/api/queues?page=1&page_size=200&sort=messages&sort_reverse=true&columns="+rabbitQueueColumns)
	if err != nil {
		return err
	}
	kept, err := emitRabbitQueues(out, b, now)
	if err != nil {
		return err
	}
	if b, err = getBody(ctx, c, c.URL+"/api/overview"); err != nil {
		return err
	}
	if err := EmitRabbitOverview(out, b, now); err != nil {
		return err
	}
	optional := []struct {
		path string
		emit func(sink.Sink, []byte, time.Time) error
	}{
		{"/api/nodes", EmitRabbitNodes},
		{"/api/consumers?columns=queue.name,queue.vhost,prefetch_count,ack_required,activity_status", func(o sink.Sink, b []byte, t time.Time) error {
			return emitRabbitConsumers(o, b, kept, t)
		}},
		{"/api/stream/consumers", EmitRabbitStreamConsumers},
		{"/api/shovels", EmitRabbitShovels},
		{"/api/federation-links", EmitRabbitFederation},
	}
	for _, o := range optional {
		b, err := getBody(ctx, c, c.URL+o.path)
		if err == nil {
			err = o.emit(out, b, now)
		}
		if err != nil {
			slog.Debug("rabbitmq: optional endpoint skipped", "path", o.path, "error", sink.Truncate(err.Error(), 200))
		}
	}
	return nil
}

type rabbitQueue struct {
	Name      string         `json:"name"`
	Vhost     string         `json:"vhost"`
	Type      string         `json:"type"`
	State     string         `json:"state"`
	Messages  float64        `json:"messages"`
	Ready     float64        `json:"messages_ready"`
	Unacked   float64        `json:"messages_unacknowledged"`
	Consumers float64        `json:"consumers"`
	Capacity  any            `json:"consumer_capacity"`    // 3.12+; "" or absent without consumers
	Util      any            `json:"consumer_utilisation"` // before 3.12
	Memory    float64        `json:"memory"`
	HeadTS    any            `json:"head_message_timestamp"` // unix seconds, only when messages carry a timestamp
	Args      any            `json:"arguments"`
	Policy    any            `json:"effective_policy_definition"` // [] when no policy applies
	Leader    string         `json:"leader"`
	Members   []string       `json:"members"`
	Online    []string       `json:"online"`
	Stats     map[string]any `json:"message_stats"`
}

func rmqStr(m any, k string) string {
	mm, _ := m.(map[string]any)
	s, _ := mm[k].(string)
	return s
}

var rabbitQueueStats = [][2]string{{"publish", "published"}, {"deliver_get", "delivered"}, {"ack", "acknowledged"}, {"redeliver", "redelivered"}}

// EmitRabbitQueues parses /api/queues: a paged `{items: [...]}` object or a plain array.
func EmitRabbitQueues(out sink.Sink, body []byte, now time.Time) error {
	_, err := emitRabbitQueues(out, body, now)
	return err
}

// emitRabbitQueues emits the 200 deepest queues and returns their "vhost\x00name" keys.
func emitRabbitQueues(out sink.Sink, body []byte, now time.Time) (map[string]bool, error) {
	var qs []rabbitQueue
	var paged struct {
		Items []rabbitQueue `json:"items"`
	}
	if err := json.Unmarshal(body, &paged); err == nil && paged.Items != nil {
		qs = paged.Items
	} else if err := json.Unmarshal(body, &qs); err != nil {
		return nil, fmt.Errorf("rabbitmq: not a queue list: %w", err)
	}
	sort.SliceStable(qs, func(i, j int) bool { return qs[i].Messages > qs[j].Messages })
	if len(qs) > 200 {
		qs = qs[:200]
	}
	kept := make(map[string]bool, len(qs))
	for _, q := range qs {
		kept[q.Vhost+"\x00"+q.Name] = true
		a := map[string]string{"queue": q.Name, "vhost": q.Vhost}
		out.Gauge("rabbitmq.queue.messages", "{messages}", q.Messages, a, now)
		out.Gauge("rabbitmq.queue.unacknowledged", "{messages}", q.Unacked, a, now)
		out.Gauge("rabbitmq.queue.consumers", "{consumers}", q.Consumers, a, now)
		out.Gauge("rabbitmq.queue.ready", "{messages}", q.Ready, a, now)
		out.Gauge("rabbitmq.queue.memory", "By", q.Memory, a, now)
		if f, ok := num(q.Capacity); ok {
			out.Gauge("rabbitmq.queue.consumer_capacity", "1", f, a, now)
		} else if f, ok := num(q.Util); ok {
			out.Gauge("rabbitmq.queue.consumer_capacity", "1", f, a, now)
		}
		if ts, ok := num(q.HeadTS); ok && ts > 0 {
			out.Gauge("rabbitmq.queue.oldest_message_age", "s", max(0, float64(now.Unix())-ts), a, now)
		}
		if len(q.Members) > 0 {
			out.Gauge("rabbitmq.queue.members", "{nodes}", float64(len(q.Members)), a, now)
			out.Gauge("rabbitmq.queue.members_offline", "{nodes}", float64(max(0, len(q.Members)-len(q.Online))), a, now)
		}
		for _, s := range rabbitQueueStats {
			if f, ok := num(q.Stats[s[0]]); ok {
				out.Sum("rabbitmq.queue.messages."+s[1], "{messages}", f, a, now)
			}
		}
		dlx := rmqStr(q.Args, "x-dead-letter-exchange")
		if dlx == "" {
			dlx = rmqStr(q.Policy, "dead-letter-exchange")
		}
		typ := q.Type
		if typ == "" {
			typ = "classic"
		}
		out.Gauge("rabbitmq.queue.info", "1", 1, map[string]string{"queue": q.Name, "vhost": q.Vhost, "type": typ,
			"state": q.State, "leader": q.Leader, "dead_letter_exchange": dlx}, now)
	}
	return kept, nil
}
