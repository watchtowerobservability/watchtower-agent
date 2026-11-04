package integrations

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Cumulative counters of /api/overview: message_stats and churn_rates hold totals since the
// node started next to `<name>_details` rate objects, which are ignored (rates come from rate()).
var (
	rabbitMessageStats = [][2]string{
		{"publish", "published"}, {"deliver_get", "delivered"}, {"ack", "acknowledged"}, {"redeliver", "redelivered"},
		{"confirm", "confirmed"}, {"return_unroutable", "returned_unroutable"}, {"drop_unroutable", "dropped_unroutable"},
	}
	rabbitChurn = [][2]string{
		{"connection_created", "rabbitmq.connections.created"}, {"connection_closed", "rabbitmq.connections.closed"},
		{"channel_created", "rabbitmq.channels.created"}, {"channel_closed", "rabbitmq.channels.closed"},
		{"queue_declared", "rabbitmq.queues.declared"}, {"queue_created", "rabbitmq.queues.created"},
		{"queue_deleted", "rabbitmq.queues.deleted"},
	}
	rabbitTotals = [][2]string{{"connections", "{connections}"}, {"channels", "{channels}"}, {"queues", "{queues}"}, {"consumers", "{consumers}"}}
)

// EmitRabbitOverview parses /api/overview; every series carries the cluster name.
func EmitRabbitOverview(out sink.Sink, body []byte, now time.Time) error {
	var v struct {
		Cluster string         `json:"cluster_name"`
		Stats   map[string]any `json:"message_stats"` // [] on a fresh node
		Churn   map[string]any `json:"churn_rates"`
		Totals  map[string]any `json:"object_totals"`
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil || probe["object_totals"] == nil {
		return fmt.Errorf("rabbitmq: not /api/overview: %v", err)
	}
	for k, dst := range map[string]any{"cluster_name": &v.Cluster, "message_stats": &v.Stats, "churn_rates": &v.Churn, "object_totals": &v.Totals} {
		_ = json.Unmarshal(probe[k], dst) // an empty list where an object is expected leaves the map nil
	}
	a := map[string]string{"cluster": v.Cluster}
	for _, s := range rabbitMessageStats {
		if f, ok := num(v.Stats[s[0]]); ok {
			out.Sum("rabbitmq.messages."+s[1], "{messages}", f, a, now)
		}
	}
	for _, s := range rabbitChurn {
		if f, ok := num(v.Churn[s[0]]); ok {
			out.Sum(s[1], "1", f, a, now)
		}
	}
	for _, s := range rabbitTotals {
		if f, ok := num(v.Totals[s[0]]); ok {
			out.Gauge("rabbitmq."+s[0], s[1], f, a, now)
		}
	}
	return nil
}

// EmitRabbitNodes parses /api/nodes (needs the monitoring tag): resource use and alarms per node.
func EmitRabbitNodes(out sink.Sink, body []byte, now time.Time) error {
	var ns []struct {
		Name       string  `json:"name"`
		Running    bool    `json:"running"`
		MemUsed    float64 `json:"mem_used"`
		MemLimit   float64 `json:"mem_limit"`
		MemAlarm   bool    `json:"mem_alarm"`
		DiskFree   float64 `json:"disk_free"`
		DiskLimit  float64 `json:"disk_free_limit"`
		DiskAlarm  bool    `json:"disk_free_alarm"`
		FDUsed     float64 `json:"fd_used"`
		FDTotal    float64 `json:"fd_total"`
		Sockets    float64 `json:"sockets_used"`
		ProcUsed   float64 `json:"proc_used"`
		ProcTotal  float64 `json:"proc_total"`
		RunQueue   float64 `json:"run_queue"`
		Partitions []any   `json:"partitions"`
	}
	if err := json.Unmarshal(body, &ns); err != nil {
		return fmt.Errorf("rabbitmq: not /api/nodes: %w", err)
	}
	for _, n := range ns {
		a := map[string]string{"node": n.Name}
		for _, g := range []struct {
			name, unit string
			v          float64
		}{
			{"running", "1", b2f(n.Running)}, {"memory.used", "By", n.MemUsed}, {"memory.limit", "By", n.MemLimit},
			{"memory.alarm", "1", b2f(n.MemAlarm)}, {"disk.free", "By", n.DiskFree}, {"disk.free_limit", "By", n.DiskLimit},
			{"disk.alarm", "1", b2f(n.DiskAlarm)}, {"fd.used", "{files}", n.FDUsed}, {"fd.limit", "{files}", n.FDTotal},
			{"sockets.used", "{sockets}", n.Sockets}, {"processes.used", "{processes}", n.ProcUsed},
			{"processes.limit", "{processes}", n.ProcTotal}, {"run_queue", "{processes}", n.RunQueue},
			{"partitions", "{nodes}", float64(len(n.Partitions))},
		} {
			out.Gauge("rabbitmq.node."+g.name, g.unit, g.v, a, now)
		}
	}
	return nil
}

// emitRabbitConsumers parses /api/consumers into per-queue counts of the consumer settings that
// cause trouble: unlimited prefetch (prefetch_count 0), automatic ack and single-active waiting.
// Only the queues kept by emitRabbitQueues are reported, so consumers cannot add series.
func emitRabbitConsumers(out sink.Sink, body []byte, kept map[string]bool, now time.Time) error {
	var cs []struct {
		Queue    struct{ Name, Vhost string } `json:"queue"`
		Prefetch float64                      `json:"prefetch_count"`
		AckReq   bool                         `json:"ack_required"`
		Status   string                       `json:"activity_status"`
	}
	if err := json.Unmarshal(body, &cs); err != nil {
		return fmt.Errorf("rabbitmq: not /api/consumers: %w", err)
	}
	type counts struct{ unlimited, autoAck, waiting float64 }
	per := map[[2]string]*counts{}
	for _, c := range cs {
		k := [2]string{c.Queue.Vhost, c.Queue.Name}
		if !kept[k[0]+"\x00"+k[1]] {
			continue
		}
		n := per[k]
		if n == nil {
			n = &counts{}
			per[k] = n
		}
		n.unlimited += b2f(c.Prefetch == 0 && c.AckReq) // prefetch is meaningless without acks
		n.autoAck += b2f(!c.AckReq)
		n.waiting += b2f(c.Status == "waiting")
	}
	for k, n := range per {
		a := map[string]string{"vhost": k[0], "queue": k[1]}
		out.Gauge("rabbitmq.queue.consumers.unlimited_prefetch", "{consumers}", n.unlimited, a, now)
		out.Gauge("rabbitmq.queue.consumers.auto_ack", "{consumers}", n.autoAck, a, now)
		out.Gauge("rabbitmq.queue.consumers.waiting", "{consumers}", n.waiting, a, now)
	}
	return nil
}

// EmitRabbitStreamConsumers parses /api/stream/consumers (rabbitmq_stream_management): per stream,
// the consumer count and the largest offset lag (messages between a consumer and the stream end).
func EmitRabbitStreamConsumers(out sink.Sink, body []byte, now time.Time) error {
	var cs []struct {
		Queue     struct{ Name, Vhost string } `json:"queue"`
		OffsetLag float64                      `json:"offset_lag"`
	}
	if err := json.Unmarshal(body, &cs); err != nil {
		return fmt.Errorf("rabbitmq: not /api/stream/consumers: %w", err)
	}
	type agg struct{ n, lag float64 }
	per := map[[2]string]*agg{}
	for _, c := range cs {
		k := [2]string{c.Queue.Vhost, c.Queue.Name}
		if per[k] == nil {
			if len(per) >= 200 {
				continue
			}
			per[k] = &agg{}
		}
		per[k].n++
		per[k].lag = max(per[k].lag, c.OffsetLag)
	}
	for k, g := range per {
		a := map[string]string{"vhost": k[0], "stream": k[1]}
		out.Gauge("rabbitmq.stream.consumers", "{consumers}", g.n, a, now)
		out.Gauge("rabbitmq.stream.consumer_lag.max", "{messages}", g.lag, a, now)
	}
	return nil
}

// EmitRabbitShovels parses /api/shovels: 1 while a shovel is running, 0 otherwise.
func EmitRabbitShovels(out sink.Sink, body []byte, now time.Time) error {
	var ss []struct{ Name, Vhost, Type, State string }
	if err := json.Unmarshal(body, &ss); err != nil {
		return fmt.Errorf("rabbitmq: not /api/shovels: %w", err)
	}
	for i, s := range ss {
		if i == 500 {
			break
		}
		out.Gauge("rabbitmq.shovel.up", "1", b2f(s.State == "running"),
			map[string]string{"shovel": s.Name, "vhost": s.Vhost, "type": s.Type, "state": s.State}, now)
	}
	return nil
}

// EmitRabbitFederation parses /api/federation-links: 1 while a link is running, 0 otherwise.
func EmitRabbitFederation(out sink.Sink, body []byte, now time.Time) error {
	var ls []struct {
		Upstream string `json:"upstream"`
		Vhost    string `json:"vhost"`
		Type     string `json:"type"`
		Exchange string `json:"exchange"`
		Queue    string `json:"queue"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(body, &ls); err != nil {
		return fmt.Errorf("rabbitmq: not /api/federation-links: %w", err)
	}
	for i, l := range ls {
		if i == 500 {
			break
		}
		target := l.Exchange
		if l.Type == "queue" {
			target = l.Queue
		}
		out.Gauge("rabbitmq.federation.link.up", "1", b2f(l.Status == "running"), map[string]string{"upstream": l.Upstream,
			"vhost": l.Vhost, "type": l.Type, "target": target, "status": l.Status}, now)
	}
	return nil
}
