package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// fixtureServer answers each path of routes with the recorded JSON in testdata/<dir>/<file>;
// any other path is a 404 (a plugin that is not enabled).
func fixtureServer(t *testing.T, dir string, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join("testdata", dir, f))
		if err != nil {
			t.Errorf("fixture %s: %v", f, err)
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sample returns the value of the first series named name whose attributes include want.
func sample(r *sink.Recorder, name string, want map[string]string) (float64, bool) {
next:
	for _, s := range r.Snapshot() {
		if s.Name != name {
			continue
		}
		for k, v := range want {
			if s.Attrs[k] != v {
				continue next
			}
		}
		return s.Value, true
	}
	return 0, false
}

func wantSample(t *testing.T, r *sink.Recorder, name string, want map[string]string, v float64) {
	t.Helper()
	got, ok := sample(r, name, want)
	if !ok {
		t.Errorf("no %s%v", name, want)
	} else if got != v {
		t.Errorf("%s%v = %v, want %v", name, want, got, v)
	}
}

func TestRabbitMQDeepFixtures(t *testing.T) {
	srv := fixtureServer(t, "rabbitmq", map[string]string{
		"/api/queues": "queues.json", "/api/overview": "overview.json", "/api/nodes": "nodes.json",
		"/api/consumers": "consumers.json", "/api/stream/consumers": "stream_consumers.json",
		"/api/shovels": "shovels.json", "/api/federation-links": "federation-links.json",
	})
	now := time.Unix(1793620600, 0) // the orders head message is 600 s old
	r := &sink.Recorder{}
	if err := collectRabbit(context.Background(), HTTPConfig{URL: srv.URL}, r, now); err != nil {
		t.Fatal(err)
	}
	orders := map[string]string{"queue": "orders", "vhost": "/"}
	wantSample(t, r, "rabbitmq.queue.ready", orders, 115)
	wantSample(t, r, "rabbitmq.queue.consumer_capacity", orders, 0.42)
	wantSample(t, r, "rabbitmq.queue.oldest_message_age", orders, 600)
	wantSample(t, r, "rabbitmq.queue.members_offline", orders, 1)
	wantSample(t, r, "rabbitmq.queue.messages.redelivered", orders, 37)
	wantSample(t, r, "rabbitmq.queue.info", map[string]string{"queue": "orders", "type": "quorum", "dead_letter_exchange": "orders.dlx", "leader": "rabbit@node1"}, 1)
	wantSample(t, r, "rabbitmq.queue.info", map[string]string{"queue": "jobs", "type": "classic", "dead_letter_exchange": "jobs.dlx"}, 1)
	if _, ok := sample(r, "rabbitmq.queue.consumer_capacity", map[string]string{"queue": "jobs"}); ok {
		t.Error("an empty consumer_utilisation must not become a point")
	}
	if _, ok := sample(r, "rabbitmq.queue.oldest_message_age", map[string]string{"queue": "events"}); ok {
		t.Error("no head timestamp, no age")
	}
	c := map[string]string{"cluster": "rabbit@node1"}
	wantSample(t, r, "rabbitmq.messages.dropped_unroutable", c, 3)
	wantSample(t, r, "rabbitmq.connections.created", c, 40)
	wantSample(t, r, "rabbitmq.connections", c, 2)
	n2 := map[string]string{"node": "rabbit@node2"}
	wantSample(t, r, "rabbitmq.node.memory.alarm", n2, 1)
	wantSample(t, r, "rabbitmq.node.disk.alarm", n2, 1)
	wantSample(t, r, "rabbitmq.node.partitions", n2, 1)
	wantSample(t, r, "rabbitmq.node.memory.alarm", map[string]string{"node": "rabbit@node1"}, 0)
	wantSample(t, r, "rabbitmq.queue.consumers.unlimited_prefetch", orders, 1)
	wantSample(t, r, "rabbitmq.queue.consumers.auto_ack", orders, 1)
	wantSample(t, r, "rabbitmq.queue.consumers.waiting", map[string]string{"queue": "jobs"}, 1)
	if _, ok := sample(r, "rabbitmq.queue.consumers.auto_ack", map[string]string{"queue": "not-kept"}); ok {
		t.Error("consumers of a queue outside the top 200 must not add series")
	}
	wantSample(t, r, "rabbitmq.stream.consumer_lag.max", map[string]string{"stream": "events"}, 20000)
	wantSample(t, r, "rabbitmq.stream.consumers", map[string]string{"stream": "events"}, 2)
	wantSample(t, r, "rabbitmq.shovel.up", map[string]string{"shovel": "legacy"}, 0)
	wantSample(t, r, "rabbitmq.shovel.up", map[string]string{"shovel": "to-dr"}, 1)
	wantSample(t, r, "rabbitmq.federation.link.up", map[string]string{"upstream": "dc3", "target": "orders"}, 0)
	wantSample(t, r, "rabbitmq.federation.link.up", map[string]string{"upstream": "dc2", "target": "events"}, 1)
}

func TestRabbitMQOptionalEndpointsMayBeMissing(t *testing.T) {
	srv := fixtureServer(t, "rabbitmq", map[string]string{"/api/queues": "queues.json", "/api/overview": "overview.json"})
	r := &sink.Recorder{}
	if err := collectRabbit(context.Background(), HTTPConfig{URL: srv.URL}, r, time.Now()); err != nil {
		t.Fatalf("missing plugins or monitoring tag must not fail the round: %v", err)
	}
	wantNames(t, r, "rabbitmq.queue.messages", "rabbitmq.messages.published")
	srv = fixtureServer(t, "rabbitmq", map[string]string{"/api/queues": "queues.json"})
	if err := collectRabbit(context.Background(), HTTPConfig{URL: srv.URL}, r, time.Now()); err == nil {
		t.Fatal("an unreadable overview fails the round")
	}
	if err := EmitRabbitOverview(r, []byte(`{"message_stats":[],"object_totals":{"queues":0}}`), time.Now()); err != nil {
		t.Fatalf("a fresh node lists message_stats as []: %v", err)
	}
}
