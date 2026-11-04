package integrations

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Reply helpers for the recorded Redis fixtures.
func rInt(n string) string  { return ":" + n + "\r\n" }
func rBulk(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }
func rArr(xs ...string) string {
	out := "*" + strconv.Itoa(len(xs)) + "\r\n"
	for _, x := range xs {
		out += rBulk(x)
	}
	return out
}

// runRedisFixture serves replies (command line -> raw RESP) over a pipe, runs one framework's
// collector body against it and returns the recorded points. Unknown commands get a nil reply.
func runRedisFixture(t *testing.T, fw string, cfg JobQueueConfig, replies map[string]string, now time.Time) map[string]float64 {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		for {
			v, err := jqRead(r, 0)
			if err != nil {
				return
			}
			var parts []string
			for _, a := range v.([]any) {
				parts = append(parts, a.(string))
			}
			reply, ok := replies[strings.Join(parts, " ")]
			if !ok {
				reply = "$-1\r\n"
			}
			if _, err := server.Write([]byte(reply)); err != nil {
				return
			}
		}
	}()
	cfg.framework = fw
	if err := cfg.check(); err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	e := &jqEmit{out: rec, fw: fw, now: now, seen: map[string]map[string]string{}, got: map[string]bool{}}
	rc := &jqRedis{w: client, r: bufio.NewReader(client)}
	jqRedisBodies[fw](rc, &cfg, e)
	if rc.err != nil {
		t.Fatal(rc.err)
	}
	return jqValues(rec)
}

func wantPoints(t *testing.T, got map[string]float64, want map[string]float64) {
	t.Helper()
	for k, w := range want {
		if g, ok := got[k]; !ok || g != w {
			t.Errorf("%s = %v (present %v), want %v", k, g, ok, w)
		}
	}
}

func TestJQReadErrorsAndNil(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("$-1\r\n-WRONGTYPE nope\r\n*1\r\n:5\r\n"))
	if v, err := jqRead(r, 0); v != nil || err != nil {
		t.Fatalf("nil: %v %v", v, err)
	}
	if _, err := jqRead(r, 0); err == nil || !strings.Contains(err.Error(), "WRONGTYPE") {
		t.Fatalf("error reply: %v", err)
	}
	if v, _ := jqRead(r, 0); v.([]any)[0] != int64(5) {
		t.Fatalf("array: %v", v)
	}
}

func TestEpochAge(t *testing.T) {
	now := time.Unix(1_700_000_100, 0)
	if a := epochAge(1_700_000_000.5, now); a != 99.5 {
		t.Fatalf("seconds: %v", a)
	}
	if a := epochAge(1_700_000_000_000, now); a != 100 {
		t.Fatalf("ms: %v", a)
	}
	if epochAge(0, now) != 0 {
		t.Fatal("missing")
	}
}

func TestSidekiqFixture(t *testing.T) {
	now := time.Unix(1_700_000_100, 0)
	got := runRedisFixture(t, "sidekiq", JobQueueConfig{Addr: "x:6379", Prefix: "app:"}, map[string]string{
		"SMEMBERS app:queues":         rArr("default", "mail"),
		"LLEN app:queue:default":      rInt("7"),
		"LINDEX app:queue:default -1": rBulk(`{"class":"HardJob","jid":"a1","enqueued_at":1700000040.0}`),
		"LLEN app:queue:mail":         rInt("0"),
		"ZCARD app:schedule":          rInt("3"),
		"ZCARD app:retry":             rInt("2"),
		"ZCARD app:dead":              rInt("1"),
		"SMEMBERS app:processes":      rArr("host:1:abc", "host:2:dead"),
		"HGET app:host:1:abc busy":    rBulk("4"),
		"GET app:stat:processed":      rBulk("1234"),
		"GET app:stat:failed":         rBulk("12"),
	}, now)
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|default|waiting": 7, "job_queue_oldest_waiting_age_seconds|default|": 60,
		"job_queue_jobs|mail|waiting": 0, "job_queue_oldest_waiting_age_seconds|mail|": 0,
		"job_queue_jobs|*|scheduled": 3, "job_queue_jobs|*|retry": 2, "job_queue_jobs|*|dead": 1,
		"job_queue_jobs|*|active": 4, "job_queue_workers|*|": 1,
		"job_queue_processed_total|*|": 1234, "job_queue_failed_total|*|": 12,
	})
}

func TestResqueFixture(t *testing.T) {
	got := runRedisFixture(t, "resque", JobQueueConfig{Addr: "x:6379"}, map[string]string{
		"SMEMBERS resque:queues":                               rArr("high"),
		"LLEN resque:queue:high":                               rInt("9"),
		"LLEN resque:failed":                                   rInt("4"),
		"SMEMBERS resque:workers":                              rArr("h:1:high", "h:2:high"),
		"EXISTS resque:worker:h:1:high resque:worker:h:2:high": rInt("1"),
		"GET resque:stat:processed":                            rBulk("88"),
		"GET resque:stat:failed":                               rBulk("5"),
	}, time.Now())
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|high|waiting": 9, "job_queue_jobs|*|dead": 4, "job_queue_jobs|*|active": 1,
		"job_queue_workers|*|": 2, "job_queue_processed_total|*|": 88, "job_queue_failed_total|*|": 5,
	})
}

func TestCeleryFixture(t *testing.T) {
	now := time.Unix(1_700_003_600, 0)
	got := runRedisFixture(t, "celery", JobQueueConfig{Addr: "x:6379", Queues: []string{"celery"}}, map[string]string{
		"LLEN celery":                          rInt("5"),
		"LLEN celery\x06\x169":                 rInt("2"),
		"HLEN unacked":                         rInt("3"),
		"ZCOUNT unacked_index -inf 1700000000": rInt("1"),
	}, now)
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|celery|waiting": 7, "job_queue_jobs|*|active": 3, "job_queue_stalled_jobs|*|": 1,
	})
}

func TestRQFixture(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 30, 0, time.UTC)
	got := runRedisFixture(t, "rq", JobQueueConfig{Addr: "x:6379"}, map[string]string{
		"SMEMBERS rq:queues":            rArr("rq:queue:default"),
		"LLEN rq:queue:default":         rInt("3"),
		"LINDEX rq:queue:default 0":     rBulk("job-1"),
		"HGET rq:job:job-1 enqueued_at": rBulk("2026-11-02T12:00:00.500000Z"),
		"ZCARD rq:wip:default":          rInt("2"),
		"ZCOUNT rq:wip:default -inf (" + strconv.FormatInt(now.Unix(), 10): rInt("1"),
		"ZCARD rq:scheduled:default":                                       rInt("4"),
		"ZCARD rq:deferred:default":                                        rInt("1"),
		"ZCARD rq:failed:default":                                          rInt("6"),
		"SCARD rq:workers:default":                                         rInt("2"),
	}, now)
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|default|waiting": 3, "job_queue_oldest_waiting_age_seconds|default|": 29.5,
		"job_queue_jobs|default|active": 2, "job_queue_stalled_jobs|default|": 1,
		"job_queue_jobs|default|scheduled": 4, "job_queue_jobs|default|blocked": 1,
		"job_queue_jobs|default|dead": 6, "job_queue_workers|default|": 2,
	})
	if a := isoAge("2026-11-02T12:00:00", now); a != 30 {
		t.Fatalf("no zone: %v", a)
	}
}

func TestDramatiqFixture(t *testing.T) {
	now := time.UnixMilli(1_700_000_100_000)
	got := runRedisFixture(t, "dramatiq", JobQueueConfig{Addr: "x:6379", Queues: []string{"default"}}, map[string]string{
		"ZRANGEBYSCORE dramatiq:__heartbeats__ 1700000040000 +inf": rArr("w1"),
		"LLEN dramatiq:default":              rInt("2"),
		"LINDEX dramatiq:default 0":          rBulk("m1"),
		"HGET dramatiq:default.msgs m1":      rBulk(`{"queue_name":"default","message_id":"m1","message_timestamp":1700000090000}`),
		"LLEN dramatiq:default.DQ":           rInt("1"),
		"ZCARD dramatiq:default.XQ":          rInt("3"),
		"SCARD dramatiq:__acks__.w1.default": rInt("4"),
	}, now)
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|default|waiting": 2, "job_queue_oldest_waiting_age_seconds|default|": 10,
		"job_queue_jobs|default|scheduled": 1, "job_queue_jobs|default|dead": 3,
		"job_queue_jobs|default|active": 4, "job_queue_workers|*|": 1,
	})
}

func TestHorizonFixture(t *testing.T) {
	now := time.Unix(1_700_000_100, 0)
	got := runRedisFixture(t, "horizon", JobQueueConfig{Addr: "x:6379", Queues: []string{"default"}}, map[string]string{
		"LLEN laravel_database_queues:default":                             rInt("8"),
		"LINDEX laravel_database_queues:default 0":                         rBulk(`{"uuid":"u1","displayName":"App\\Jobs\\Mail","pushedAt":"1700000070.25"}`),
		"ZCARD laravel_database_queues:default:delayed":                    rInt("2"),
		"ZCARD laravel_database_queues:default:reserved":                   rInt("3"),
		"ZCOUNT laravel_database_queues:default:reserved -inf (1700000100": rInt("1"),
		"ZCARD laravel_horizon:failed_jobs":                                rInt("5"),
		"ZRANGE laravel_horizon:supervisors 0 -1":                          rArr("host-a:supervisor-1"),
		"HGET laravel_horizon:supervisor:host-a:supervisor-1 processes":    rBulk(`{"redis:default":3,"redis:mail":2}`),
	}, now)
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|default|waiting": 8, "job_queue_oldest_waiting_age_seconds|default|": 29.75,
		"job_queue_jobs|default|scheduled": 2, "job_queue_jobs|default|active": 3,
		"job_queue_stalled_jobs|default|": 1, "job_queue_jobs|*|dead": 5, "job_queue_workers|*|": 5,
	})
}

func TestAsynqFixture(t *testing.T) {
	now := time.Unix(1_700_000_100, 0)
	got := runRedisFixture(t, "asynq", JobQueueConfig{Addr: "x:6379"}, map[string]string{
		"SMEMBERS asynq:queues":                          rArr("critical"),
		"LLEN asynq:{critical}:pending":                  rInt("6"),
		"LINDEX asynq:{critical}:pending -1":             rBulk("t1"),
		"HGET asynq:{critical}:t:t1 pending_since":       rBulk("1700000088000000000"),
		"LLEN asynq:{critical}:active":                   rInt("2"),
		"ZCARD asynq:{critical}:scheduled":               rInt("1"),
		"ZCARD asynq:{critical}:retry":                   rInt("3"),
		"ZCARD asynq:{critical}:archived":                rInt("4"),
		"ZCOUNT asynq:{critical}:lease -inf (1700000100": rInt("1"),
		"GET asynq:{critical}:processed":                 rBulk("500"),
		"GET asynq:{critical}:failed":                    rBulk("7"),
		"ZCOUNT asynq:servers 1700000100 +inf":           rInt("2"),
	}, now)
	wantPoints(t, got, map[string]float64{
		"job_queue_jobs|critical|waiting": 6, "job_queue_oldest_waiting_age_seconds|critical|": 12,
		"job_queue_jobs|critical|active": 2, "job_queue_jobs|critical|scheduled": 1,
		"job_queue_jobs|critical|retry": 3, "job_queue_jobs|critical|dead": 4,
		"job_queue_stalled_jobs|critical|": 1, "job_queue_processed_total|critical|": 500,
		"job_queue_failed_total|critical|": 7, "job_queue_workers|*|": 2,
	})
}
