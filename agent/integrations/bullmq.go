package integrations

// BullMQ queue health (W35): job counts per state, the age of the oldest waiting job and
// stalled jobs, read straight from BullMQ's Redis keys (`<prefix>:<queue>:wait|active|...`) so
// no change to the application is needed.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// BullMQConfig is the bullmq module's config. RedisDSN is local-file only (it may carry the
// password): `redis://[user:password@]host[:port][/db]`, or `rediss://` for TLS.
type BullMQConfig struct {
	Base
	RedisDSN string   `json:"redis_dsn"`
	Prefix   string   `json:"prefix"` // BullMQ's key prefix, default "bull"
	Queues   []string `json:"queues"`
}

func (c *BullMQConfig) check() error {
	if _, err := parseRedisDSN(c.RedisDSN); err != nil {
		return fmt.Errorf("bullmq: %w", err)
	}
	if len(c.Queues) == 0 || len(c.Queues) > 100 {
		return errors.New("bullmq: queues needs 1 to 100 queue names")
	}
	for _, q := range c.Queues {
		if q == "" || strings.ContainsAny(q, " \t\r\n") {
			return fmt.Errorf("bullmq: queue name %q is empty or has whitespace", q)
		}
	}
	return nil
}

// redisTarget is a parsed redis DSN.
type redisTarget struct {
	cfg RedisConfig
	db  int
}

func parseRedisDSN(dsn string) (redisTarget, error) {
	var t redisTarget
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Hostname() == "" {
		return t, errors.New("redis_dsn must be redis://[user:password@]host[:port][/db] (or rediss://)")
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	t.cfg = RedisConfig{Addr: net.JoinHostPort(u.Hostname(), port), TLS: u.Scheme == "rediss"}
	if u.User != nil {
		t.cfg.Password, _ = u.User.Password()
		if t.cfg.Password == "" { // redis://:pass@ and redis://pass@ both mean a password only
			t.cfg.Password = u.User.Username()
		} else if u.User.Username() != "default" {
			t.cfg.Username = u.User.Username()
		}
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		if t.db, err = strconv.Atoi(p); err != nil || t.db < 0 {
			return t, errors.New("redis_dsn database must be a number")
		}
	}
	return t, nil
}

// bullmqStates maps each reported state to BullMQ's key suffix and the command that counts it.
var bullmqStates = []struct{ state, suffix, cmd string }{
	{"waiting", "wait", "LLEN"}, {"active", "active", "LLEN"}, {"paused", "paused", "LLEN"},
	{"delayed", "delayed", "ZCARD"}, {"prioritized", "prioritized", "ZCARD"},
	{"failed", "failed", "ZCARD"}, {"completed", "completed", "ZCARD"},
}

// bullmqStalled is the per-queue stalled-event cursor and running count (the module's state).
type bullmqStalled struct {
	last  map[string]string
	total map[string]float64
}

// BullMQ collects queue depth per state, oldest waiting age and stalled jobs per queue.
func BullMQ(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &BullMQConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.Prefix == "" {
		c.Prefix = "bull"
	}
	t, _ := parseRedisDSN(c.RedisDSN) // checked by load
	st := &bullmqStalled{last: map[string]string{}, total: map[string]float64{}}
	return Loop(ctx, "bullmq", c.Base, 15*time.Second, out, func(ctx context.Context, now time.Time) error {
		return collectBullMQ(ctx, t, c.Prefix, c.Queues, st, out, now)
	})
}

func collectBullMQ(ctx context.Context, t redisTarget, prefix string, queues []string, st *bullmqStalled,
	out sink.Sink, now time.Time,
) error {
	conn, err := dial(ctx, t.cfg.Addr, t.cfg.TLS)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	r := bufio.NewReader(conn)
	call := func(args ...string) (any, error) {
		if err := respWrite(conn, args...); err != nil {
			return nil, err
		}
		return bullRespRead(r, 0)
	}
	if t.cfg.Password != "" {
		args := []string{"AUTH", t.cfg.Password}
		if t.cfg.Username != "" {
			args = []string{"AUTH", t.cfg.Username, t.cfg.Password}
		}
		if _, err := call(args...); err != nil {
			return errors.New("redis AUTH failed")
		}
	}
	if t.db > 0 {
		if _, err := call("SELECT", strconv.Itoa(t.db)); err != nil {
			return err
		}
	}
	for _, q := range queues {
		k := prefix + ":" + q + ":"
		a := map[string]string{"queue": q}
		for _, s := range bullmqStates {
			v, err := call(s.cmd, k+s.suffix)
			if err != nil {
				return err
			}
			n, _ := v.(int64)
			out.Gauge("bullmq_jobs", "{jobs}", float64(n), sink.With(a, "state", s.state), now)
		}
		// Producers LPUSH and workers take from the right, so the tail is the oldest job.
		age := 0.0
		if id, _ := call("LINDEX", k+"wait", "-1"); id != nil {
			if v, err := call("HMGET", k+fmt.Sprint(id), "timestamp", "delay"); err == nil {
				if f, ok := v.([]any); ok && len(f) == 2 {
					age = oldestAge(f[0], f[1], now)
				}
			}
		}
		out.Gauge("bullmq_oldest_waiting_age_seconds", "s", age, a, now)
		if err := bullmqStalledEvents(call, k+"events", q, st, now); err != nil {
			return err
		}
		out.Sum("bullmq_stalled_total", "{jobs}", st.total[q], a, now)
	}
	return nil
}

// oldestAge is the seconds since a job became ready: its creation timestamp (ms) plus its delay.
func oldestAge(ts, delay any, now time.Time) float64 {
	t, err := strconv.ParseFloat(fmt.Sprint(ts), 64)
	if err != nil {
		return 0
	}
	if d, err := strconv.ParseFloat(fmt.Sprint(delay), 64); err == nil {
		t += d
	}
	return max(0, float64(now.UnixMilli())-t) / 1000
}

// bullmqStalledEvents counts `stalled` entries of the queue's event stream since the last round.
// The first round only sets the cursor, so history is not counted as new stalls.
func bullmqStalledEvents(call func(...string) (any, error), key, q string, st *bullmqStalled, now time.Time) error {
	last, ok := st.last[q]
	if !ok {
		st.last[q] = strconv.FormatInt(now.UnixMilli(), 10) + "-0"
		return nil
	}
	for page := 0; page < 10; page++ { // at most 10k events per round
		v, err := call("XRANGE", key, last, "+", "COUNT", "1000")
		if err != nil {
			return err
		}
		entries, _ := v.([]any)
		n, next, more := countStalled(entries, last)
		st.total[q] += float64(n)
		last = next
		if !more {
			break
		}
	}
	st.last[q] = last
	return nil
}

// countStalled counts XRANGE entries whose `event` field is `stalled`, skipping the entry equal
// to after (XRANGE's start is inclusive). It returns the last id seen and whether a full page
// came back.
func countStalled(entries []any, after string) (n int, last string, more bool) {
	last = after
	for _, e := range entries {
		pair, ok := e.([]any)
		if !ok || len(pair) != 2 {
			continue
		}
		id, _ := pair[0].(string)
		if id == after {
			continue
		}
		last = id
		fields, _ := pair[1].([]any)
		for i := 0; i+1 < len(fields); i += 2 {
			if fields[i] == "event" && fields[i+1] == "stalled" {
				n++
			}
		}
	}
	return n, last, len(entries) >= 1000
}

// bullRespRead reads one RESP2 reply: string, int64, nil (null bulk or array) or []any. An error
// reply is returned as an error.
func bullRespRead(r *bufio.Reader, depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("redis: reply nested too deeply")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("empty reply")
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
			return nil, errors.New("bad bulk length")
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
			return nil, errors.New("bad array length")
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := bullRespRead(r, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	default:
		return nil, errors.New("redis: unexpected reply " + sink.Truncate(line, 40))
	}
}
