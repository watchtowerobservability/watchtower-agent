package integrations

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func newJQEmit(fw string, now time.Time) (*jqEmit, *sink.Recorder) {
	r := &sink.Recorder{}
	return &jqEmit{out: r, fw: fw, now: now, seen: map[string]map[string]string{}, got: map[string]bool{}}, r
}

func TestFaktoryHash(t *testing.T) {
	one := sha256.Sum256([]byte("pw" + "salt"))
	if faktoryHash("pw", "salt", 1) != hex.EncodeToString(one[:]) {
		t.Fatal("one iteration")
	}
	two := sha256.Sum256(one[:])
	if faktoryHash("pw", "salt", 2) != hex.EncodeToString(two[:]) {
		t.Fatal("two iterations")
	}
}

// Recorded from `faktory` 1.9 (INFO after HELLO), trimmed.
const faktoryInfoFixture = `{"faktory":{"default_size":4,"total_failures":3,"total_processed":120,"total_enqueued":9,"total_queues":2,` +
	`"queues":{"default":4,"critical":5},"tasks":{"Busy":{"size":2,"reaper":true},"Dead":{"size":1,"cycles":0},` +
	`"Retries":{"size":6,"enqueued":0},"Scheduled":{"size":7,"enqueued":0},"Workers":{"size":3,"reaped":0}}},` +
	`"server":{"description":"Faktory","faktory_version":"1.9.0","uptime":100,"connections":4,"command_count":50,"used_memory_mb":12}}`

func TestFaktoryHandshakeAndInfo(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	gotHello := make(chan string, 1)
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		_, _ = server.Write([]byte(`+HI {"v":2,"s":"abc","i":3}` + "\r\n"))
		line, _ := r.ReadString('\n')
		gotHello <- line
		_, _ = server.Write([]byte("+OK\r\n"))
		if l, _ := r.ReadString('\n'); l != "INFO\r\n" {
			return
		}
		_, _ = server.Write([]byte(rBulk(faktoryInfoFixture)))
		_, _ = r.ReadString('\n')
	}()
	info, err := faktoryTalk(client, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if h := <-gotHello; !strings.HasPrefix(h, "HELLO {") || !strings.Contains(h, `"pwdhash":"`+faktoryHash("secret", "abc", 3)+`"`) {
		t.Fatalf("hello %q", h)
	}
	e, rec := newJQEmit("faktory", time.Now())
	if err := emitFaktory(e, &JobQueueConfig{}, info); err != nil {
		t.Fatal(err)
	}
	wantPoints(t, jqValues(rec), map[string]float64{
		"job_queue_jobs|default|waiting": 4, "job_queue_jobs|critical|waiting": 5,
		"job_queue_jobs|*|active": 2, "job_queue_jobs|*|scheduled": 7, "job_queue_jobs|*|retry": 6,
		"job_queue_jobs|*|dead": 1, "job_queue_workers|*|": 3,
		"job_queue_processed_total|*|": 120, "job_queue_failed_total|*|": 3,
	})
}

func TestFaktoryNeedsPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = server.Write([]byte(`+HI {"v":2,"s":"abc","i":1}` + "\r\n"))
		server.Close()
	}()
	if _, err := faktoryTalk(client, ""); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("err %v", err)
	}
}

func TestTemporalFixture(t *testing.T) {
	// Recorded DescribeTaskQueue replies (Temporal 1.27 HTTP API), one per task queue type.
	replies := map[string]string{
		"TASK_QUEUE_TYPE_WORKFLOW": `{"pollers":[{"lastAccessTime":"2026-11-02T12:00:00Z","identity":"1@host-a","ratePerSecond":100000}],` +
			`"stats":{"approximateBacklogCount":"12","approximateBacklogAge":"42.500s","tasksAddRate":1.5,"tasksDispatchRate":1.2}}`,
		"TASK_QUEUE_TYPE_ACTIVITY": `{"pollers":[{"identity":"1@host-a"},{"identity":"2@host-b"}],"stats":{"approximateBacklogCount":"3","approximateBacklogAge":"5s"}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/prod/task-queues/orders" || r.Header.Get("Authorization") != "Bearer k" ||
			r.URL.Query().Get("reportStats") != "true" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, replies[r.URL.Query().Get("taskQueueType")])
	}))
	defer srv.Close()
	c := &JobQueueConfig{framework: "temporal", URL: srv.URL, Token: "k", Namespace: "prod", Queues: []string{"orders"}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	e, rec := newJQEmit("temporal", time.Now())
	if err := jobFrameworks["temporal"].collect(context.Background(), c, e); err != nil {
		t.Fatal(err)
	}
	wantPoints(t, jqValues(rec), map[string]float64{
		"job_queue_jobs|orders|waiting": 15, "job_queue_oldest_waiting_age_seconds|orders|": 42.5,
		"job_queue_workers|orders|": 2,
	})
}
