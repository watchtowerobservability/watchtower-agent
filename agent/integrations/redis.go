package integrations

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// RedisConfig is the redis module's config. Addr and Password are local-file only.
type RedisConfig struct {
	Base
	Addr     string `json:"addr"` // host:port
	Password string `json:"password"`
	Username string `json:"username"`
	TLS      bool   `json:"tls"`
	// Streams are the stream keys to inspect (XINFO); empty means the ones SCAN TYPE stream finds.
	Streams []string `json:"streams"`
	// KeySample is how many keys a keyspace pass (every 20th round) sizes with MEMORY USAGE; 0 means 1000, -1 off.
	KeySample int `json:"key_sample"`
}

func (c *RedisConfig) check() error {
	if c.Addr == "" {
		return errors.New("redis: addr is required (in the agent's own config file)")
	}
	return nil
}

func (c *MemcachedConfig) check() error {
	if c.Addr == "" {
		return errors.New("memcached: addr is required (in the agent's own config file)")
	}
	return nil
}

const maxReply = 4 << 20

// Redis runs INFO over RESP and emits the server, client, memory, stats and replication
// sections, the deeper reads of redis_deep.go (Valkey, Dragonfly and KeyDB speak the same), then
// streams, their consumer groups and consumers (redis_streams.go).
func Redis(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &RedisConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	streams := &redisStreams{}
	deep := newRedisDeep(c.KeySample)
	return Loop(ctx, "redis", c.Base, 15*time.Second, out, func(ctx context.Context, now time.Time) error {
		s, err := redisOpen(ctx, *c)
		if err != nil {
			return err
		}
		defer s.conn.Close()
		// INFO all adds commandstats, latencystats and errorstats; fall back for servers without it.
		info, err := s.str("INFO", "all")
		if err != nil {
			if info, err = s.str("INFO"); err != nil {
				return err
			}
		}
		m := ParseRedisInfo(info)
		EmitRedis(out, m, now)
		deep.collect(s, m, out, now)
		if err := streams.collect(ctx, *c, out, now); err != nil {
			slog.Debug("redis: streams skipped", "error", sink.Truncate(err.Error(), 200))
		}
		return nil
	})
}

func dial(ctx context.Context, addr string, useTLS bool) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if useTLS {
		return (&tls.Dialer{NetDialer: &d, Config: &tls.Config{MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

// respSession is one authenticated connection.
type respSession struct {
	conn net.Conn
	r    *bufio.Reader
}

func redisOpen(ctx context.Context, c RedisConfig) (*respSession, error) {
	conn, err := dial(ctx, c.Addr, c.TLS)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	s := &respSession{conn: conn, r: bufio.NewReader(conn)}
	if c.Password != "" {
		args := []string{"AUTH", c.Password}
		if c.Username != "" {
			args = []string{"AUTH", c.Username, c.Password}
		}
		if _, err := s.do(args...); err != nil {
			conn.Close()
			return nil, errors.New("redis AUTH failed")
		}
	}
	return s, nil
}

// do sends one command and reads its reply.
func (s *respSession) do(args ...string) (any, error) {
	if err := respWrite(s.conn, args...); err != nil {
		return nil, err
	}
	return respRead(s.r, 0)
}

// str runs a command whose reply is a string.
func (s *respSession) str(args ...string) (string, error) {
	v, err := s.do(args...)
	if err != nil {
		return "", err
	}
	t, ok := v.(string)
	if !ok {
		return "", errors.New("redis: unexpected reply type")
	}
	return t, nil
}

// pipeline sends every command, then reads one reply each (an error reply becomes nil).
func (s *respSession) pipeline(cmds [][]string) ([]any, error) {
	var b strings.Builder
	for _, c := range cmds {
		_ = respWrite(&b, c...)
	}
	if _, err := io.WriteString(s.conn, b.String()); err != nil {
		return nil, err
	}
	out := make([]any, len(cmds))
	for i := range cmds {
		v, err := respRead(s.r, 0)
		if err != nil {
			if _, isReply := err.(respError); !isReply {
				return nil, err
			}
		}
		out[i] = v
	}
	return out, nil
}

func respWrite(w io.Writer, args ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// respError is an error reply from the server (the connection is still usable).
type respError string

func (e respError) Error() string { return "redis: " + string(e) }

// respRead reads one RESP2/RESP3 reply: strings, integers (int64), arrays ([]any) and nil.
// Maps (RESP3) are read as flat arrays. Nesting and sizes are bounded.
func respRead(r *bufio.Reader, depth int) (any, error) {
	if depth > 8 {
		return nil, errors.New("redis: reply nested too deep")
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
	case '-', '!':
		return nil, respError(sink.Truncate(line[1:], 120))
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		return n, err
	case ',':
		return strconv.ParseFloat(line[1:], 64)
	case '_':
		return nil, nil
	case '$', '=':
		n, err := strconv.Atoi(line[1:])
		if n == -1 {
			return nil, nil
		}
		if err != nil || n < 0 || n > maxReply {
			return nil, errors.New("bad bulk length")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*', '%', '~', '>':
		n, err := strconv.Atoi(line[1:])
		if n == -1 {
			return nil, nil
		}
		if line[0] == '%' {
			n *= 2
		}
		if err != nil || n < 0 || n > 100000 {
			return nil, errors.New("bad array length")
		}
		arr := make([]any, 0, n)
		for range n {
			v, err := respRead(r, depth+1)
			if err != nil {
				if _, isReply := err.(respError); !isReply {
					return nil, err
				}
			}
			arr = append(arr, v)
		}
		return arr, nil
	default:
		return nil, errors.New("redis: " + sink.Truncate(line, 120))
	}
}

// ParseRedisInfo reads INFO text: `key:value` lines, section headers and blanks skipped.
func ParseRedisInfo(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			m[k] = v
		}
	}
	return m
}

var redisGauges = map[string]string{
	"connected_clients": "redis.clients.connected", "blocked_clients": "redis.clients.blocked",
	"used_memory": "redis.memory.used", "used_memory_rss": "redis.memory.rss", "maxmemory": "redis.memory.max",
	"mem_fragmentation_ratio": "redis.memory.fragmentation_ratio", "connected_slaves": "redis.replicas.connected",
	"master_repl_offset": "redis.replication.offset", "rdb_changes_since_last_save": "redis.rdb.changes_since_save",
	"uptime_in_seconds": "redis.uptime", "master_last_io_seconds_ago": "redis.replication.last_io_age",
}

var redisCounters = map[string]string{
	"total_commands_processed": "redis.commands.processed", "total_connections_received": "redis.connections.received",
	"keyspace_hits": "redis.keyspace.hits", "keyspace_misses": "redis.keyspace.misses",
	"evicted_keys": "redis.keys.evicted", "expired_keys": "redis.keys.expired",
	"rejected_connections": "redis.connections.rejected",
}

// EmitRedis turns parsed INFO into metrics.
func EmitRedis(out sink.Sink, info map[string]string, now time.Time) {
	for k, v := range info {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			if n, ok := redisGauges[k]; ok {
				out.Gauge(n, "1", f, nil, now)
			} else if n, ok := redisCounters[k]; ok {
				out.Sum(n, "1", f, nil, now)
			}
		}
		// db0:keys=1,expires=0,avg_ttl=0
		if strings.HasPrefix(k, "db") && strings.Contains(v, "keys=") {
			for _, kv := range strings.Split(v, ",") {
				if name, val, ok := strings.Cut(kv, "="); ok && name == "keys" {
					if f, err := strconv.ParseFloat(val, 64); err == nil {
						out.Gauge("redis.db.keys", "{keys}", f, map[string]string{"db": k}, now)
					}
				}
			}
		}
	}
	if v, ok := info["master_link_status"]; ok { // replicas only
		up := 0.0
		if v == "up" {
			up = 1
		}
		out.Gauge("redis.replication.link_up", "1", up, nil, now)
	}
}

// MemcachedConfig is the memcached module's config.
type MemcachedConfig struct {
	Base
	Addr string `json:"addr"`
}

// Memcached sends `stats` over the text protocol.
func Memcached(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &MemcachedConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "memcached", c.Base, 15*time.Second, out, func(ctx context.Context, now time.Time) error {
		conn, err := dial(ctx, c.Addr, false)
		if err != nil {
			return err
		}
		defer conn.Close()
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		if _, err := io.WriteString(conn, "stats\r\n"); err != nil {
			return err
		}
		r := bufio.NewReader(io.LimitReader(conn, maxReply))
		st, err := ReadMemcachedStats(r)
		if err != nil {
			return err
		}
		EmitMemcached(out, st, now)
		// Slab classes: where memory goes and which item sizes are evicted (best effort).
		if _, err := io.WriteString(conn, "stats slabs\r\nstats items\r\n"); err != nil {
			return nil
		}
		slabs, err := ReadMemcachedStats(r)
		if err != nil {
			return nil
		}
		items, err := ReadMemcachedStats(r)
		if err != nil {
			return nil
		}
		EmitMemcachedSlabs(out, slabs, items, now)
		return nil
	})
}

// ReadMemcachedStats reads `STAT name value` lines up to END.
func ReadMemcachedStats(r *bufio.Reader) (map[string]string, error) {
	m := map[string]string{}
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		f := strings.Fields(l)
		switch {
		case len(f) == 1 && f[0] == "END":
			return m, nil
		case len(f) == 3 && f[0] == "STAT":
			m[f[1]] = f[2]
		default:
			return nil, errors.New("memcached: " + sink.Truncate(strings.TrimSpace(l), 120))
		}
	}
}

// EmitMemcached emits the headline stats.
func EmitMemcached(out sink.Sink, st map[string]string, now time.Time) {
	for k, n := range map[string]string{"curr_connections": "memcached.connections.current", "bytes": "memcached.memory.used",
		"limit_maxbytes": "memcached.memory.max", "curr_items": "memcached.items.current"} {
		if f, err := strconv.ParseFloat(st[k], 64); err == nil {
			out.Gauge(n, "1", f, nil, now)
		}
	}
	for k, n := range map[string]string{"get_hits": "memcached.gets.hits", "get_misses": "memcached.gets.misses",
		"evictions": "memcached.evictions", "total_connections": "memcached.connections.total",
		"cmd_get": "memcached.commands.get", "cmd_set": "memcached.commands.set", "reclaimed": "memcached.items.reclaimed",
		"evicted_unfetched": "memcached.evictions.unfetched", "expired_unfetched": "memcached.items.expired_unfetched",
		"listen_disabled_num": "memcached.connections.listen_disabled", "rejected_connections": "memcached.connections.rejected"} {
		if f, err := strconv.ParseFloat(st[k], 64); err == nil {
			out.Sum(n, "1", f, nil, now)
		}
	}
}

// EmitMemcachedSlabs emits per slab class memory (`stats slabs`) and item eviction figures
// (`stats items`): which item sizes are starved of memory.
func EmitMemcachedSlabs(out sink.Sink, slabs, items map[string]string, now time.Time) {
	gauges := map[string]string{"chunk_size": "memcached.slab.chunk_size", "used_chunks": "memcached.slab.chunks.used",
		"free_chunks": "memcached.slab.chunks.free", "total_pages": "memcached.slab.pages", "mem_requested": "memcached.slab.memory.requested"}
	for k, v := range slabs {
		class, stat, ok := strings.Cut(k, ":")
		if n, known := gauges[stat]; ok && known {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				out.Gauge(n, "1", f, map[string]string{"slab_class": class}, now)
			}
		}
	}
	for k, v := range items {
		parts := strings.Split(k, ":") // items:<class>:<stat>
		if len(parts) != 3 {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		a := map[string]string{"slab_class": parts[1]}
		switch parts[2] {
		case "number":
			out.Gauge("memcached.slab.items", "{items}", f, a, now)
		case "age":
			out.Gauge("memcached.slab.oldest_item_age", "s", f, a, now)
		case "evicted_time":
			if ev := items["items:"+parts[1]+":evicted"]; ev == "" || ev == "0" {
				continue // 0 means nothing was evicted, not an item evicted at age 0
			}
			out.Gauge("memcached.slab.last_evicted_age", "s", f, a, now)
		case "evicted":
			out.Sum("memcached.slab.evictions", "{items}", f, a, now)
		case "outofmemory":
			out.Sum("memcached.slab.out_of_memory", "{errors}", f, a, now)
		}
	}
}
