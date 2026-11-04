package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// EMQX reads the EMQX 5 REST API (an API key and secret as username and password): cluster
// stats and counters, per node status and resources, and active alarms.
func EMQX(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "emqx", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		for _, ep := range []struct {
			path string
			emit func(sink.Sink, []byte, time.Time) error
		}{
			{"/api/v5/stats?aggregate=true", EmitEMQXStats},
			{"/api/v5/metrics?aggregate=true", EmitEMQXMetrics},
			{"/api/v5/nodes", EmitEMQXNodes},
			{"/api/v5/alarms?activated=true&limit=1000", EmitEMQXAlarms},
		} {
			b, err := getBody(ctx, *c, c.URL+ep.path)
			if err != nil {
				return err
			}
			if err := ep.emit(out, b, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func emqxObject(body []byte, what string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("emqx: not %s: %w", what, err)
	}
	return m, nil
}

// EmitEMQXStats parses /api/v5/stats: current counts (`x.count`) and their peaks (`x.max`).
func EmitEMQXStats(out sink.Sink, body []byte, now time.Time) error {
	m, err := emqxObject(body, "/api/v5/stats")
	if err != nil {
		return err
	}
	for k, v := range m {
		f, ok := v.(float64)
		if !ok {
			continue
		}
		if base, ok := strings.CutSuffix(k, ".count"); ok {
			out.Gauge("emqx."+base, "1", f, nil, now)
		} else if base, ok := strings.CutSuffix(k, ".max"); ok {
			out.Gauge("emqx."+base+".max", "1", f, nil, now)
		}
	}
	return nil
}

// emqxCounters are the /api/v5/metrics counters forwarded (all cumulative).
var emqxCounters = []string{
	"messages.received", "messages.sent", "messages.delivered", "messages.acked", "messages.publish",
	"messages.dropped", "messages.dropped.no_subscribers", "messages.dropped.await_pubrel_timeout",
	"messages.forward", "messages.retained", "messages.qos0.received", "messages.qos1.received",
	"messages.qos2.received", "delivery.dropped", "delivery.dropped.queue_full", "delivery.dropped.expired",
	"delivery.dropped.too_large", "delivery.dropped.no_local", "delivery.dropped.qos0_msg",
	"client.connected", "client.disconnected", "client.connack", "client.auth.failure", "client.authenticate",
	"authorization.deny", "authorization.allow", "session.created", "session.discarded", "session.takenover",
	"bytes.received", "bytes.sent", "packets.received", "packets.sent",
}

// EmitEMQXMetrics parses /api/v5/metrics?aggregate=true.
func EmitEMQXMetrics(out sink.Sink, body []byte, now time.Time) error {
	m, err := emqxObject(body, "/api/v5/metrics")
	if err != nil {
		return err
	}
	for _, k := range emqxCounters {
		if f, ok := m[k].(float64); ok {
			out.Sum("emqx."+k, "1", f, nil, now)
		}
	}
	return nil
}

// EmitEMQXNodes parses /api/v5/nodes.
func EmitEMQXNodes(out sink.Sink, body []byte, now time.Time) error {
	var ns []struct {
		Node         string  `json:"node"`
		Status       string  `json:"node_status"`
		Connections  float64 `json:"connections"`
		Live         float64 `json:"live_connections"`
		MemoryUsed   any     `json:"memory_used"` // a number, or "12.00M" on older 5.x
		MemoryTotal  any     `json:"memory_total"`
		Load1        any     `json:"load1"`
		MaxFDs       float64 `json:"max_fds"`
		ProcessUsed  float64 `json:"process_used"`
		ProcessLimit float64 `json:"process_available"`
		Uptime       float64 `json:"uptime"` // ms
	}
	if err := json.Unmarshal(body, &ns); err != nil {
		return fmt.Errorf("emqx: not /api/v5/nodes: %w", err)
	}
	for _, n := range ns {
		a := map[string]string{"node": n.Node}
		out.Gauge("emqx.node.running", "1", b2f(n.Status == "running"), a, now)
		out.Gauge("emqx.node.connections", "{connections}", n.Connections, a, now)
		out.Gauge("emqx.node.live_connections", "{connections}", n.Live, a, now)
		out.Gauge("emqx.node.processes.used", "{processes}", n.ProcessUsed, a, now)
		out.Gauge("emqx.node.processes.limit", "{processes}", n.ProcessLimit, a, now)
		out.Gauge("emqx.node.fd.limit", "{files}", n.MaxFDs, a, now)
		out.Gauge("emqx.node.uptime", "s", n.Uptime/1000, a, now)
		if f, ok := n.MemoryUsed.(float64); ok {
			out.Gauge("emqx.node.memory.used", "By", f, a, now)
		}
		if f, ok := n.MemoryTotal.(float64); ok {
			out.Gauge("emqx.node.memory.total", "By", f, a, now)
		}
		if f, ok := n.Load1.(float64); ok {
			out.Gauge("emqx.node.load1", "1", f, a, now)
		}
	}
	return nil
}

// EmitEMQXAlarms parses /api/v5/alarms?activated=true: active alarms per name (high_system_memory_usage,
// conn_congestion, ...).
func EmitEMQXAlarms(out sink.Sink, body []byte, now time.Time) error {
	var v struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("emqx: not /api/v5/alarms: %w", err)
	}
	per := map[string]float64{}
	for _, a := range v.Data {
		name, _, _ := strings.Cut(a.Name, "/") // conn_congestion/<clientid>/<user> would be one series per client
		per[name]++
	}
	out.Gauge("emqx.alarms.active", "{alarms}", float64(len(v.Data)), nil, now)
	for name, n := range per {
		out.Gauge("emqx.alarm.active", "{alarms}", n, map[string]string{"alarm": name}, now)
	}
	return nil
}
