package integrations

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// sections.
func Redis(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &RedisConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "redis", c.Base, 15*time.Second, out, func(ctx context.Context, now time.Time) error {
		info, err := redisInfo(ctx, *c)
		if err != nil {
			return err
		}
		EmitRedis(out, ParseRedisInfo(info), now)
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

func redisInfo(ctx context.Context, c RedisConfig) (string, error) {
	conn, err := dial(ctx, c.Addr, c.TLS)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	r := bufio.NewReader(conn)
	if c.Password != "" {
		args := []string{"AUTH", c.Password}
		if c.Username != "" {
			args = []string{"AUTH", c.Username, c.Password}
		}
		if _, err := respDo(conn, r, args...); err != nil {
			return "", errors.New("redis AUTH failed")
		}
	}
	return respDo(conn, r, "INFO")
}

// respDo sends one command and reads a simple string, error or bulk string reply.
func respDo(w io.Writer, r *bufio.Reader, args ...string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return "", err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 || n > maxReply {
			return "", errors.New("bad bulk length")
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	default:
		return "", errors.New("redis: " + sink.Truncate(line, 120))
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
		st, err := ReadMemcachedStats(bufio.NewReader(io.LimitReader(conn, maxReply)))
		if err != nil {
			return err
		}
		EmitMemcached(out, st, now)
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
		"evictions": "memcached.evictions", "total_connections": "memcached.connections.total"} {
		if f, err := strconv.ParseFloat(st[k], 64); err == nil {
			out.Sum(n, "1", f, nil, now)
		}
	}
}
