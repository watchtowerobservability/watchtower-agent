package integrations

// Redis-backed job frameworks: each reads the framework's documented key layout with plain
// read commands (LLEN, ZCARD, LINDEX, HGET, SMEMBERS, GET), never KEYS or SCAN.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// shortcut: a second RESP reader beside bullmq.go's respRead (fix/agentdbm); merge the two once
// both branches land.

// jqRedis is a RESP2 client with a sticky error: after the first failure every call returns
// nil, and the collector reports the error once at the end of the round.
type jqRedis struct {
	w   io.Writer
	r   *bufio.Reader
	err error
}

func (rc *jqRedis) do(args ...string) any {
	if rc.err != nil {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(rc.w, b.String()); err != nil {
		rc.err = err
		return nil
	}
	v, err := jqRead(rc.r, 0)
	if err != nil {
		rc.err = err
	}
	return v
}

// num is an integer or numeric string reply as a float (0 for nil).
func (rc *jqRedis) num(args ...string) float64 { return jqFloat(rc.do(args...)) }

func (rc *jqRedis) str(args ...string) string {
	s, _ := rc.do(args...).(string)
	return s
}

func (rc *jqRedis) strs(args ...string) []string {
	vs, _ := rc.do(args...).([]any)
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func jqFloat(v any) float64 {
	switch v := v.(type) {
	case int64:
		return float64(v)
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

// jqRedisBodies keeps each Redis framework's round body for the fixture tests.
var jqRedisBodies = map[string]func(*jqRedis, *JobQueueConfig, *jqEmit){}

// addRedisFramework registers a Redis-backed framework with its default key prefix.
func addRedisFramework(name, prefix string, needQueues bool, f func(rc *jqRedis, c *JobQueueConfig, e *jqEmit)) {
	jqRedisBodies[name] = f
	jobFrameworks[name] = jobFramework{backend: "redis", def: prefix, needQueues: needQueues, collect: redisJobs(f)}
}

// redisJobs returns a collector that connects (AUTH, SELECT) and runs f.
func redisJobs(f func(rc *jqRedis, c *JobQueueConfig, e *jqEmit)) func(context.Context, *JobQueueConfig, *jqEmit) error {
	return func(ctx context.Context, c *JobQueueConfig, e *jqEmit) error {
		conn, err := dial(ctx, c.Addr, c.TLS)
		if err != nil {
			return err
		}
		defer conn.Close()
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		rc := &jqRedis{w: conn, r: bufio.NewReader(conn)}
		if c.Password != "" {
			args := []string{"AUTH", c.Password}
			if c.Username != "" {
				args = []string{"AUTH", c.Username, c.Password}
			}
			if rc.do(args...); rc.err != nil {
				return errors.New("redis AUTH failed")
			}
		}
		if c.DB > 0 {
			rc.do("SELECT", strconv.Itoa(c.DB))
		}
		if rc.err == nil {
			f(rc, c, e)
		}
		return rc.err
	}
}

// jqRead reads one RESP2 reply: string, int64, nil or []any; an error reply is an error.
func jqRead(r *bufio.Reader, depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("redis: reply nested too deeply")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("redis: empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, errors.New("redis: " + sink.Truncate(line[1:], 120))
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n > maxReply {
			return nil, errors.New("redis: bad bulk length")
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n > 100_000 {
			return nil, errors.New("redis: bad array length")
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := jqRead(r, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, errors.New("redis: unexpected reply " + sink.Truncate(line, 40))
}

// epochAge is the seconds from an epoch timestamp (seconds, or milliseconds when larger than
// 1e11) to now; 0 when ts is missing.
func epochAge(ts float64, now time.Time) float64 {
	if ts <= 0 {
		return 0
	}
	if ts > 1e11 {
		ts /= 1000
	}
	return max(0, float64(now.UnixNano())/1e9-ts)
}

// jsonField reads one top-level numeric field (number or numeric string) of a JSON payload.
func jsonField(payload, field string) float64 {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return 0
	}
	return jqFloat(m[field])
}

// first caps a list read from the store.
func first(s []string, n int) []string { return s[:min(len(s), n)] }

func init() {
	// Sidekiq (Ruby): <prefix>queues, queue:<q> lists (LPUSH, the oldest at the right end, its
	// enqueued_at in seconds or, Sidekiq 8, milliseconds), schedule/retry/dead sorted sets, the
	// processes set with a `busy` count per live process, stat:processed and stat:failed.
	addRedisFramework("sidekiq", "", false, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		for _, q := range c.queues(rc.strs("SMEMBERS", p+"queues")) {
			k := p + "queue:" + q
			e.jobs(q, "waiting", rc.num("LLEN", k))
			e.age(q, epochAge(jsonField(rc.str("LINDEX", k, "-1"), "enqueued_at"), e.now))
		}
		e.jobs("*", "scheduled", rc.num("ZCARD", p+"schedule"))
		e.jobs("*", "retry", rc.num("ZCARD", p+"retry"))
		e.jobs("*", "dead", rc.num("ZCARD", p+"dead"))
		busy, live := 0.0, 0.0
		for _, id := range first(rc.strs("SMEMBERS", p+"processes"), 1000) {
			if b := rc.do("HGET", p+id, "busy"); b != nil { // the process hash expires when it dies
				live++
				busy += jqFloat(b)
			}
		}
		e.jobs("*", "active", busy)
		e.workers("*", live)
		e.total("processed", "*", rc.num("GET", p+"stat:processed"))
		e.total("failed", "*", rc.num("GET", p+"stat:failed"))
	})
}

func init() {
	// Resque (Ruby): <prefix>queues, queue:<q> lists (payloads carry no enqueue time, so no
	// age), the failed list (dead), the workers set and worker:<id> keys of busy workers.
	addRedisFramework("resque", "resque:", false, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		for _, q := range c.queues(rc.strs("SMEMBERS", p+"queues")) {
			e.jobs(q, "waiting", rc.num("LLEN", p+"queue:"+q))
		}
		e.jobs("*", "dead", rc.num("LLEN", p+"failed"))
		workers := first(rc.strs("SMEMBERS", p+"workers"), 1000)
		busy := 0.0
		if len(workers) > 0 {
			args := []string{"EXISTS"}
			for _, w := range workers {
				args = append(args, p+"worker:"+w)
			}
			busy = rc.num(args...)
		}
		e.jobs("*", "active", busy)
		e.workers("*", float64(len(workers)))
		e.total("processed", "*", rc.num("GET", p+"stat:processed"))
		e.total("failed", "*", rc.num("GET", p+"stat:failed"))
	})
}

func init() {
	// Celery on Redis (kombu): one list per queue plus one per priority step (<q>\x06\x163, 6,
	// 9). Delivered but unacknowledged messages sit in the `unacked` hash, scored by delivery time
	// in `unacked_index`; one older than stall_after (match it to visibility_timeout, default 1h)
	// is stalled and kombu will redeliver it. Messages carry no enqueue time, so no age. Celery
	// on RabbitMQ is read by the rabbitmq module.
	addRedisFramework("celery", "", true, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		for _, q := range c.queues(nil) {
			n := 0.0
			for _, k := range []string{q, q + "\x06\x163", q + "\x06\x166", q + "\x06\x169"} {
				n += rc.num("LLEN", p+k)
			}
			e.jobs(q, "waiting", n)
		}
		e.jobs("*", "active", rc.num("HLEN", p+"unacked"))
		cut := float64(e.now.Add(-c.stall).Unix())
		e.stalled("*", rc.num("ZCOUNT", p+"unacked_index", "-inf", strconv.FormatFloat(cut, 'f', 0, 64)))
	})
}

// isoAge is the seconds since an ISO-8601 UTC time (RQ writes 2006-01-02T15:04:05.999999Z,
// older versions without the Z); 0 when missing or unparseable.
func isoAge(s string, now time.Time) float64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		if t, err = time.Parse("2006-01-02T15:04:05", s); err != nil {
			return 0
		}
	}
	return max(0, now.Sub(t).Seconds())
}

func init() {
	// RQ (Python): rq:queues lists rq:queue:<q> lists (RPUSH, the oldest first, its job hash's
	// enqueued_at), and per queue the registries: rq:wip (started, scored by expiry, so an entry
	// past now was abandoned: stalled), rq:scheduled, rq:deferred (blocked on dependencies),
	// rq:failed (dead) and the rq:workers:<q> set.
	addRedisFramework("rq", "", false, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		var found []string
		for _, k := range rc.strs("SMEMBERS", p+"rq:queues") {
			found = append(found, strings.TrimPrefix(k, p+"rq:queue:"))
		}
		now := "(" + strconv.FormatInt(e.now.Unix(), 10)
		for _, q := range c.queues(found) {
			k := p + "rq:queue:" + q
			e.jobs(q, "waiting", rc.num("LLEN", k))
			age := 0.0
			if id := rc.str("LINDEX", k, "0"); id != "" {
				age = isoAge(rc.str("HGET", p+"rq:job:"+id, "enqueued_at"), e.now)
			}
			e.age(q, age)
			e.jobs(q, "active", rc.num("ZCARD", p+"rq:wip:"+q))
			e.stalled(q, rc.num("ZCOUNT", p+"rq:wip:"+q, "-inf", now))
			e.jobs(q, "scheduled", rc.num("ZCARD", p+"rq:scheduled:"+q))
			e.jobs(q, "blocked", rc.num("ZCARD", p+"rq:deferred:"+q))
			e.jobs(q, "dead", rc.num("ZCARD", p+"rq:failed:"+q))
			e.workers(q, rc.num("SCARD", p+"rq:workers:"+q))
		}
	})
}

func init() {
	// Dramatiq on Redis: <ns>:<q> lists message ids (RPUSH, the oldest first) with the bodies in
	// <ns>:<q>.msgs (message_timestamp in ms); <q>.DQ is the delay queue, <q>.XQ the dead-letter
	// set. Workers heartbeat into __heartbeats__ (ms; 60 s timeout) and hold their in-flight ids
	// in __acks__.<worker>.<q>. Dramatiq keeps no list of queues. On RabbitMQ use the rabbitmq module.
	addRedisFramework("dramatiq", "dramatiq:", true, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		cut := strconv.FormatInt(e.now.Add(-time.Minute).UnixMilli(), 10)
		workers := first(rc.strs("ZRANGEBYSCORE", p+"__heartbeats__", cut, "+inf"), 200)
		for _, q := range c.queues(nil) {
			k := p + q
			e.jobs(q, "waiting", rc.num("LLEN", k))
			age := 0.0
			if id := rc.str("LINDEX", k, "0"); id != "" {
				age = epochAge(jsonField(rc.str("HGET", k+".msgs", id), "message_timestamp"), e.now)
			}
			e.age(q, age)
			e.jobs(q, "scheduled", rc.num("LLEN", k+".DQ"))
			e.jobs(q, "dead", rc.num("ZCARD", k+".XQ"))
			active := 0.0
			for _, w := range workers {
				active += rc.num("SCARD", p+"__acks__."+w+"."+q)
			}
			e.jobs(q, "active", active)
		}
		e.workers("*", float64(len(workers)))
	})
}

func init() {
	// Laravel queues with Horizon: <prefix>queues:<q> (RPUSH, the oldest first, Horizon's
	// pushedAt or Laravel 11's createdAt), :delayed (scheduled) and :reserved, scored by when the
	// reservation expires (retry_after), so a reservation past now is stalled. Horizon's own keys
	// (horizon_prefix): failed_jobs (dead, trimmed by Horizon's retention) and the supervisors
	// with their process counts (workers). Laravel keeps no list of queues.
	addRedisFramework("horizon", "laravel_database_", true, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		now := "(" + strconv.FormatInt(e.now.Unix(), 10)
		for _, q := range c.queues(nil) {
			k := p + "queues:" + q
			e.jobs(q, "waiting", rc.num("LLEN", k))
			head := rc.str("LINDEX", k, "0")
			ts := jsonField(head, "pushedAt")
			if ts == 0 {
				ts = jsonField(head, "createdAt")
			}
			e.age(q, epochAge(ts, e.now))
			e.jobs(q, "scheduled", rc.num("ZCARD", k+":delayed"))
			e.jobs(q, "active", rc.num("ZCARD", k+":reserved"))
			e.stalled(q, rc.num("ZCOUNT", k+":reserved", "-inf", now))
		}
		hp := c.HorizonPrefix
		if hp == "" {
			hp = "laravel_horizon:"
		}
		e.jobs("*", "dead", rc.num("ZCARD", hp+"failed_jobs"))
		workers := 0.0
		for _, s := range first(rc.strs("ZRANGE", hp+"supervisors", "0", "-1"), 200) {
			var procs map[string]float64
			if json.Unmarshal([]byte(rc.str("HGET", hp+"supervisor:"+s, "processes")), &procs) == nil {
				for _, n := range procs {
					workers += n
				}
			}
		}
		e.workers("*", workers)
	})
}

func init() {
	// Asynq (Go): asynq:queues, and per queue asynq:{<q>}:pending (LPUSH, the oldest at the right
	// end, its task hash's pending_since in ns), active, scheduled, retry, archived (dead), the
	// lease set (scored by lease expiry in s, so past now is stalled) and the processed/failed
	// totals. asynq:servers is scored by expiry: live servers are the workers.
	addRedisFramework("asynq", "", false, func(rc *jqRedis, c *JobQueueConfig, e *jqEmit) {
		p := c.Prefix
		now := strconv.FormatInt(e.now.Unix(), 10)
		for _, q := range c.queues(rc.strs("SMEMBERS", p+"asynq:queues")) {
			k := p + "asynq:{" + q + "}:"
			e.jobs(q, "waiting", rc.num("LLEN", k+"pending"))
			age := 0.0
			if id := rc.str("LINDEX", k+"pending", "-1"); id != "" {
				if ns := jqFloat(rc.do("HGET", k+"t:"+id, "pending_since")); ns > 0 {
					age = max(0, float64(e.now.UnixNano())-ns) / 1e9
				}
			}
			e.age(q, age)
			e.jobs(q, "active", rc.num("LLEN", k+"active"))
			e.jobs(q, "scheduled", rc.num("ZCARD", k+"scheduled"))
			e.jobs(q, "retry", rc.num("ZCARD", k+"retry"))
			e.jobs(q, "dead", rc.num("ZCARD", k+"archived"))
			e.stalled(q, rc.num("ZCOUNT", k+"lease", "-inf", "("+now))
			e.total("processed", q, rc.num("GET", k+"processed"))
			e.total("failed", q, rc.num("GET", k+"failed"))
		}
		e.workers("*", rc.num("ZCOUNT", p+"asynq:servers", now, "+inf"))
	})
}
