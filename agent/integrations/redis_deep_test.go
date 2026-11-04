package integrations

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Recorded replies of a Redis 7.2 server (RESP2), keyed by command.
var redisReplies = map[string]string{
	"AUTH": "+OK\r\n",
	"INFO": "$0\r\n\r\n", // replaced per test
	// Two entries: a SET with a value that must not leak and an old one from before the first round.
	"SLOWLOG": "*2\r\n" +
		"*6\r\n:7\r\n:%NOW%\r\n:25000\r\n*3\r\n$3\r\nSET\r\n$14\r\nuser:1234:cart\r\n$12\r\nsecret-value\r\n$15\r\n127.0.0.1:50000\r\n$0\r\n\r\n" +
		"*6\r\n:6\r\n:1000\r\n:9000\r\n*2\r\n$3\r\nGET\r\n$5\r\nold:1\r\n$15\r\n127.0.0.1:50000\r\n$0\r\n\r\n",
	"LATENCY":   "*1\r\n*4\r\n$7\r\ncommand\r\n:1700000000\r\n:120\r\n:450\r\n",
	"CLUSTER":   bulk("cluster_state:fail\r\ncluster_slots_assigned:16384\r\ncluster_slots_fail:2\r\ncluster_size:3\r\n"),
	"MEMORY":    "", // DOCTOR and USAGE differ, see serveRedis
	"RANDOMKEY": "$14\r\nuser:1234:cart\r\n",
	"OBJECT":    ":7\r\n",
}

func bulk(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }

func serveRedis(t *testing.T, info string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener")
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			v, err := respRead(r, 0)
			if err != nil {
				return
			}
			args := strs(v)
			reply := redisReplies[args[0]]
			switch args[0] {
			case "INFO":
				reply = bulk(info)
			case "MEMORY":
				if args[1] == "DOCTOR" {
					d := "Sam, I detected a few issues: high fragmentation."
					reply = bulk(d)
				} else {
					reply = ":2048\r\n"
				}
			case "SLOWLOG":
				reply = strings.Replace(reply, "%NOW%", strconv.Itoa(int(time.Now().Unix())), 1)
			}
			if _, err := c.Write([]byte(reply)); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

func TestRedisDeepRound(t *testing.T) {
	info := "# Server\r\nredis_version:7.2.4\r\nexecutable:/usr/bin/keydb-server\r\n# Memory\r\nmaxmemory_policy:allkeys-lfu\r\n" +
		"# Replication\r\nmaster_repl_offset:5000\r\nslave0:ip=10.0.0.2,port=6379,state=online,offset=4000,lag=1\r\n" +
		"# Commandstats\r\ncmdstat_get:calls=10,usec=20,usec_per_call=2.00,rejected_calls=0,failed_calls=1\r\n" +
		"# Latencystats\r\nlatency_percentiles_usec_get:p50=1.003,p99=2.007,p99.9=3.007\r\n" +
		"# Errorstats\r\nerrorstat_WRONGTYPE:count=3\r\n# Cluster\r\ncluster_enabled:1\r\n# Keyspace\r\ndb0:keys=1000,expires=10,avg_ttl=500\r\n"
	addr := serveRedis(t, info)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := redisOpen(ctx, RedisConfig{Addr: addr, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.conn.Close()
	text, err := s.str("INFO", "all")
	if err != nil {
		t.Fatal(err)
	}
	m := ParseRedisInfo(text)
	rec := &sink.Recorder{}
	d := newRedisDeep(5)
	d.collect(s, m, rec, time.Now())
	wantNames(t, rec, "redis.server.info", "redis.command.calls", "redis.command.latency", "redis.errors", "redis.replica.offset_lag",
		"redis.slowlog.entries", "redis.latency.max", "redis.cluster.state_ok", "redis.cluster.slots.fail",
		"redis.memory.doctor_issues", "redis.keyspace.pattern.bytes", "redis.keyspace.pattern.freq")
	var samples, slow int
	for _, x := range rec.Samples {
		if x.Name == "redis.server.info" && x.Attrs["db.system.name"] != "keydb" {
			t.Fatalf("system %v", x.Attrs)
		}
		if x.Name == "redis.replica.offset_lag" && x.Value != 1000 {
			t.Fatal(x.Value)
		}
		if x.Name == "redis.keyspace.pattern.bytes" && (x.Attrs["redis.key.pattern"] != "user:*:cart" || x.Value != 2048*1000) {
			t.Fatalf("pattern %v %v", x.Attrs, x.Value)
		}
		if x.Name != "" {
			continue
		}
		samples++
		if strings.Contains(x.Body, "secret-value") || strings.Contains(x.Body, "1234") {
			t.Fatalf("value leaked: %s", x.Body)
		}
		if x.Attrs["event.name"] == "db.query.sample" {
			slow++
			if !strings.Contains(x.Body, `"command":"SET user:*:cart ?"`) {
				t.Fatal(x.Body)
			}
		}
	}
	if slow != 1 || samples != 3 { // one fresh slowlog entry, the doctor's advice, the keyspace report
		t.Fatalf("samples %d slow %d", samples, slow)
	}
	if d.lastSlowID != 7 {
		t.Fatal(d.lastSlowID)
	}
}

func TestRedisSlowlogIDsResetAfterRestart(t *testing.T) {
	d := newRedisDeep(-1)
	d.lastSlowID = 500
	rec := &sink.Recorder{}
	entry := []any{[]any{int64(3), time.Now().Unix(), int64(10), []any{"HGETALL", "h:9"}}}
	d.slowlog(rec, "valkey", entry, time.Now())
	if d.lastSlowID != 3 || d.slow["hgetall"][0] != 1 {
		t.Fatalf("restart not detected: %d %v", d.lastSlowID, d.slow)
	}
}

func TestRedisSystemDetection(t *testing.T) {
	for want, info := range map[string]map[string]string{
		"dragonfly": {"dragonfly_version": "df-v1.20.0", "redis_version": "6.2.11"},
		"valkey":    {"valkey_version": "8.0.1", "redis_version": "7.2.4"},
		"redis":     {"redis_version": "7.2.4"},
	} {
		if got, _ := RedisSystem(info); got != want {
			t.Errorf("%v: got %s", info, got)
		}
	}
}
