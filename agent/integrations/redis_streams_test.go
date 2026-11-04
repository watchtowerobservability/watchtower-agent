package integrations

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// fakeRedis answers each command with testdata/redis/<ARGS_JOINED>.resp (recorded replies) and
// an error reply for anything else.
func fakeRedis(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					v, err := readRESP(r, 0)
					if err != nil {
						return
					}
					var args []string
					for _, a := range v.([]any) {
						args = append(args, a.(string))
					}
					b, err := os.ReadFile(filepath.Join("testdata", "redis", strings.Join(args, "_")+".resp"))
					if err != nil {
						b = []byte("-ERR no such key\r\n")
					}
					_, _ = c.Write(b)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestRedisStreamsFromRecordedReplies(t *testing.T) {
	addr := fakeRedis(t)
	now := time.UnixMilli(1793620600000)
	r := &sink.Recorder{}
	s := &redisStreams{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.collect(ctx, RedisConfig{Addr: addr}, r, now); err != nil {
		t.Fatal(err)
	}
	if !s.keys["orders"] || !s.keys["events"] || s.cursor != "0" {
		t.Fatalf("SCAN discovery: %v cursor %q", s.keys, s.cursor)
	}
	orders := map[string]string{"stream": "orders"}
	wantSample(t, r, "redis.stream.length", orders, 500)
	wantSample(t, r, "redis.stream.entries_added", orders, 9000)
	wantSample(t, r, "redis.stream.last_entry_age", orders, 10)
	billing := map[string]string{"stream": "orders", "group": "billing"}
	wantSample(t, r, "redis.stream.group.pending", billing, 3)
	wantSample(t, r, "redis.stream.group.lag", billing, 120)
	wantSample(t, r, "redis.stream.group.lag_time", billing, 60)
	wantSample(t, r, "redis.stream.group.oldest_pending_age", billing, 300)
	wantSample(t, r, "redis.stream.group.lag_time", map[string]string{"group": "audit"}, 0)
	wantSample(t, r, "redis.stream.consumer.idle", map[string]string{"consumer": "w2"}, 120)
	wantSample(t, r, "redis.stream.consumer.pending", map[string]string{"consumer": "w1"}, 2)
	// Redis 6.2 has no lag field: the time gap still comes from the ids.
	wantSample(t, r, "redis.stream.group.lag_time", map[string]string{"stream": "events", "group": "g"}, 1000)
	if _, ok := sample(r, "redis.stream.group.lag", map[string]string{"stream": "events"}); ok {
		t.Error("no lag field, no lag series")
	}
	s.keys["gone"] = true
	if err := s.collect(ctx, RedisConfig{Addr: addr, Streams: []string{"gone"}}, &sink.Recorder{}, now); err != nil || s.keys["gone"] {
		t.Fatalf("a deleted stream is forgotten: %v %v", err, s.keys)
	}
}

func TestReadRESPRefusesDeepAndHugeReplies(t *testing.T) {
	for _, in := range []string{"*999999999\r\n", strings.Repeat("*1\r\n", 20) + ":1\r\n", "$-5\r\n", "?\r\n"} {
		if v, err := readRESP(bufio.NewReader(strings.NewReader(in)), 0); err == nil && v != nil {
			t.Errorf("%q accepted as %v", in, v)
		}
	}
}
