package integrations

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Redis Streams caps: streams inspected, groups per stream, consumer series per round, and SCAN
// calls per round while discovering stream keys (the cursor carries over between rounds).
const maxRedisStreams, maxRedisGroups, maxRedisConsumers, redisScanCalls = 100, 50, 500, 5

// redisStreams remembers discovered stream keys and the SCAN cursor between rounds.
type redisStreams struct {
	cursor string
	keys   map[string]bool
}

// shortcut: a RESP2 reader of its own and a second connection per round; when fix/dbm-nosql's
// respSession lands, run these commands on its session instead.
type redisConn struct {
	c net.Conn
	r *bufio.Reader
}

func redisDial(ctx context.Context, c RedisConfig) (*redisConn, error) {
	conn, err := dial(ctx, c.Addr, c.TLS)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	rc := &redisConn{conn, bufio.NewReader(conn)}
	if c.Password != "" {
		args := []string{"AUTH", c.Password}
		if c.Username != "" {
			args = []string{"AUTH", c.Username, c.Password}
		}
		if _, err := rc.do(args...); err != nil {
			conn.Close()
			return nil, errors.New("redis AUTH failed")
		}
	}
	return rc, nil
}

// do sends one command and reads its reply: string, int64, []any or nil. An error reply is an
// error, and the connection stays usable.
func (rc *redisConn) do(args ...string) (any, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(rc.c, b.String()); err != nil {
		return nil, err
	}
	return readRESP(rc.r, 0)
}

func readRESP(r *bufio.Reader, depth int) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" || depth > 8 {
		return nil, errors.New("redis: bad reply")
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
		if err != nil || n > 100000 {
			return nil, errors.New("redis: bad array length")
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = readRESP(r, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, errors.New("redis: unknown reply " + sink.Truncate(line, 40))
}

// respMap turns a flat [k1, v1, k2, v2, ...] reply into a map.
func respMap(v any) map[string]any {
	a, _ := v.([]any)
	m := make(map[string]any, len(a)/2)
	for i := 0; i+1 < len(a); i += 2 {
		if k, ok := a[i].(string); ok {
			m[k] = a[i+1]
		}
	}
	return m
}

func respNum(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	return 0, false
}

// streamIDTime reads the millisecond time of a stream entry id ("1730550000000-3").
func streamIDTime(v any) (time.Time, bool) {
	s, _ := v.(string)
	ms, _, _ := strings.Cut(s, "-")
	n, err := strconv.ParseInt(ms, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(n), true
}

func ageSeconds(now, t time.Time) float64 { return max(0, now.Sub(t).Seconds()) }

// collect inspects the configured streams, or the stream keys found so far by SCAN TYPE stream.
func (s *redisStreams) collect(ctx context.Context, c RedisConfig, out sink.Sink, now time.Time) error {
	rc, err := redisDial(ctx, c)
	if err != nil {
		return err
	}
	defer rc.c.Close()
	keys := c.Streams
	if len(keys) == 0 {
		s.discover(rc)
		for k := range s.keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	nc := 0
	for i, key := range keys {
		if i == maxRedisStreams {
			break
		}
		info, err := rc.do("XINFO", "STREAM", key)
		if err != nil {
			delete(s.keys, key) // deleted or no longer a stream
			continue
		}
		groups, _ := rc.do("XINFO", "GROUPS", key)
		nc += emitRedisStream(rc, out, key, respMap(info), groups, maxRedisConsumers-nc, now)
	}
	return nil
}

// discover runs a few SCAN calls per round, continuing the cursor, and remembers stream keys.
func (s *redisStreams) discover(rc *redisConn) {
	if s.keys == nil {
		s.keys, s.cursor = map[string]bool{}, "0"
	}
	for range redisScanCalls {
		v, err := rc.do("SCAN", s.cursor, "COUNT", "1000", "TYPE", "stream")
		a, _ := v.([]any)
		if err != nil || len(a) != 2 {
			return
		}
		s.cursor, _ = a[0].(string)
		ks, _ := a[1].([]any)
		for _, k := range ks {
			if k, ok := k.(string); ok && len(s.keys) < maxRedisStreams {
				s.keys[k] = true
			}
		}
		if s.cursor == "0" || s.cursor == "" {
			s.cursor = "0"
			return
		}
	}
}

type xreader interface {
	do(args ...string) (any, error)
}

// emitRedisStream writes one stream's series, its groups' and at most budget consumer series;
// it returns how many consumer series it wrote.
func emitRedisStream(rc xreader, out sink.Sink, key string, info map[string]any, groups any, budget int, now time.Time) int {
	a := map[string]string{"stream": key}
	if f, ok := respNum(info["length"]); ok {
		out.Gauge("redis.stream.length", "{entries}", f, a, now)
	}
	if f, ok := respNum(info["entries-added"]); ok { // Redis 7+
		out.Sum("redis.stream.entries_added", "{entries}", f, a, now)
	}
	if f, ok := respNum(info["groups"]); ok {
		out.Gauge("redis.stream.groups", "{groups}", f, a, now)
	}
	last, haveLast := streamIDTime(info["last-generated-id"])
	if haveLast {
		out.Gauge("redis.stream.last_entry_age", "s", ageSeconds(now, last), a, now)
	}
	gs, _ := groups.([]any)
	n := 0
	for i, g := range gs {
		if i == maxRedisGroups {
			break
		}
		gm := respMap(g)
		name, _ := gm["name"].(string)
		ga := map[string]string{"stream": key, "group": name}
		pending, _ := respNum(gm["pending"])
		out.Gauge("redis.stream.group.pending", "{entries}", pending, ga, now)
		if f, ok := respNum(gm["consumers"]); ok {
			out.Gauge("redis.stream.group.consumers", "{consumers}", f, ga, now)
		}
		lag, hasLag := respNum(gm["lag"]) // Redis 7+; nil when the server cannot tell
		if hasLag {
			out.Gauge("redis.stream.group.lag", "{entries}", lag, ga, now)
		}
		// Entry ids are millisecond times, so the gap between the newest entry and the group's last
		// delivered one is the lag in time.
		if d, ok := streamIDTime(gm["last-delivered-id"]); ok && haveLast {
			lt := max(0, last.Sub(d).Seconds())
			if hasLag && lag == 0 {
				lt = 0
			}
			out.Gauge("redis.stream.group.lag_time", "s", lt, ga, now)
		}
		if pending > 0 {
			if p, err := rc.do("XPENDING", key, name); err == nil {
				if pa, _ := p.([]any); len(pa) >= 2 {
					if t, ok := streamIDTime(pa[1]); ok {
						out.Gauge("redis.stream.group.oldest_pending_age", "s", ageSeconds(now, t), ga, now)
					}
				}
			}
		}
		if n >= budget {
			continue
		}
		cs, _ := rc.do("XINFO", "CONSUMERS", key, name)
		csa, _ := cs.([]any)
		for _, c := range csa {
			if n >= budget {
				break
			}
			cm := respMap(c)
			cn, _ := cm["name"].(string)
			ca := map[string]string{"stream": key, "group": name, "consumer": cn}
			if f, ok := respNum(cm["pending"]); ok {
				out.Gauge("redis.stream.consumer.pending", "{entries}", f, ca, now)
			}
			if f, ok := respNum(cm["idle"]); ok {
				out.Gauge("redis.stream.consumer.idle", "s", f/1000, ca, now)
			}
			n++
		}
	}
	return n
}
