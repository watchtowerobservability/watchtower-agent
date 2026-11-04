package integrations

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRespReadNested(t *testing.T) {
	in := "*2\r\n*2\r\n$3\r\n1-0\r\n*4\r\n$5\r\nevent\r\n$7\r\nstalled\r\n$5\r\njobId\r\n$1\r\n7\r\n:42\r\n$-1\r\n-ERR nope\r\n"
	r := bufio.NewReader(strings.NewReader(in))
	v, err := bullRespRead(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n, last, more := countStalled(v.([]any)[:1], "0-0"); n != 1 || last != "1-0" || more {
		t.Fatalf("stalled %d last %q more %v", n, last, more)
	}
	if v.([]any)[1] != int64(42) {
		t.Fatalf("second element %v", v.([]any)[1])
	}
	if v, err := bullRespRead(r, 0); err != nil || v != nil {
		t.Fatalf("null bulk %v %v", v, err)
	}
	if _, err := bullRespRead(r, 0); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("error reply: %v", err)
	}
}

func TestCountStalledSkipsCursor(t *testing.T) {
	entries := []any{
		[]any{"5-0", []any{"event", "stalled"}},
		[]any{"6-0", []any{"event", "completed"}},
		[]any{"7-0", []any{"event", "stalled", "jobId", "3"}},
	}
	if n, last, _ := countStalled(entries, "5-0"); n != 1 || last != "7-0" {
		t.Fatalf("n %d last %q", n, last)
	}
}

func TestOldestAge(t *testing.T) {
	now := time.UnixMilli(100_000)
	if a := oldestAge("40000", "10000", now); a != 50 {
		t.Fatalf("age %v", a)
	}
	if a := oldestAge("40000", nil, now); a != 60 {
		t.Fatalf("no delay: %v", a)
	}
	if a := oldestAge(nil, nil, now); a != 0 {
		t.Fatalf("missing job: %v", a)
	}
}

func TestParseRedisDSN(t *testing.T) {
	for dsn, want := range map[string]redisTarget{
		"redis://:pw@cache:6380/2":      {cfg: RedisConfig{Addr: "cache:6380", Password: "pw"}, db: 2},
		"rediss://app:pw@cache":         {cfg: RedisConfig{Addr: "cache:6379", Password: "pw", Username: "app", TLS: true}},
		"redis://default:pw@127.0.0.1/": {cfg: RedisConfig{Addr: "127.0.0.1:6379", Password: "pw"}},
	} {
		got, err := parseRedisDSN(dsn)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v %v", dsn, got, err)
		}
	}
	for _, bad := range []string{"", "http://x", "redis://", "redis://h/x"} {
		if _, err := parseRedisDSN(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
