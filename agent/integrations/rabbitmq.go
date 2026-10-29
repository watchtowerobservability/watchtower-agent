package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// RabbitMQ reads the management API: queue depth, unacknowledged messages and consumers of the
// 200 deepest queues (the broker sorts and pages, so a broker with many queues stays small).
func RabbitMQ(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "rabbitmq", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		b, err := getBody(ctx, *c, c.URL+"/api/queues?page=1&page_size=200&sort=messages&sort_reverse=true&columns=name,vhost,messages,messages_unacknowledged,consumers")
		if err != nil {
			return err
		}
		return EmitRabbitQueues(out, b, now)
	})
}

type rabbitQueue struct {
	Name      string  `json:"name"`
	Vhost     string  `json:"vhost"`
	Messages  float64 `json:"messages"`
	Unacked   float64 `json:"messages_unacknowledged"`
	Consumers float64 `json:"consumers"`
}

// EmitRabbitQueues parses /api/queues: a paged `{items: [...]}` object or a plain array.
func EmitRabbitQueues(out sink.Sink, body []byte, now time.Time) error {
	var qs []rabbitQueue
	var paged struct {
		Items []rabbitQueue `json:"items"`
	}
	if err := json.Unmarshal(body, &paged); err == nil && paged.Items != nil {
		qs = paged.Items
	} else if err := json.Unmarshal(body, &qs); err != nil {
		return fmt.Errorf("rabbitmq: not a queue list: %w", err)
	}
	sort.Slice(qs, func(i, j int) bool { return qs[i].Messages > qs[j].Messages })
	if len(qs) > 200 {
		qs = qs[:200]
	}
	for _, q := range qs {
		a := map[string]string{"queue": q.Name, "vhost": q.Vhost}
		out.Gauge("rabbitmq.queue.messages", "{messages}", q.Messages, a, now)
		out.Gauge("rabbitmq.queue.unacknowledged", "{messages}", q.Unacked, a, now)
		out.Gauge("rabbitmq.queue.consumers", "{consumers}", q.Consumers, a, now)
	}
	return nil
}
