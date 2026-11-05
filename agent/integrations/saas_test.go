package integrations

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestCountActiveRuns(t *testing.T) {
	// Two full pages of 25 then a short last page; next_page_token is followed.
	pages := []runsPage{
		{Runs: make([]json.RawMessage, 25), HasMore: true, NextPageToken: "p2"},
		{Runs: make([]json.RawMessage, 25), HasMore: true, NextPageToken: "p3"},
		{Runs: make([]json.RawMessage, 7)},
	}
	i := 0
	got, err := countActiveRuns(func(token string) (runsPage, error) {
		if i > 0 && token == "" {
			t.Fatalf("page %d fetched without a token", i)
		}
		p := pages[i]
		i++
		return p, nil
	})
	if err != nil || got != 57 {
		t.Fatalf("got %d, %v; want 57", got, err)
	}

	// A fetch error propagates.
	if _, err := countActiveRuns(func(string) (runsPage, error) {
		return runsPage{}, errors.New("boom")
	}); err == nil {
		t.Fatal("expected error")
	}

	// has_more that never clears stops at maxRunPages (no infinite loop).
	n := 0
	got, err = countActiveRuns(func(string) (runsPage, error) {
		n++
		return runsPage{Runs: make([]json.RawMessage, 1), HasMore: true, NextPageToken: "x"}, nil
	})
	if err != nil || n != maxRunPages || got != maxRunPages {
		t.Fatalf("got %d over %d calls, %v; want %d", got, n, err, maxRunPages)
	}
}

func TestEmitSquidAndSnowflake(t *testing.T) {
	r := &sink.Recorder{}
	now := time.Now()
	if err := EmitSquid(r, []byte("sample_time = 1700000000.1 (Tue)\nclient_http.requests = 42\nclient_http.hits = 7\n"), now); err != nil {
		t.Fatal(err)
	}
	EmitSnowflake(r, "credits", [][]any{{"WH1", "1.5"}}, now)
	got := map[string]bool{}
	for _, p := range r.Samples {
		got[p.Name] = true
	}
	for _, n := range []string{"squid.client_http.requests", "squid.client_http.hits", "snowflake.warehouse.credits_used"} {
		if !got[n] {
			t.Errorf("missing %s in %v", n, got)
		}
	}
	if got["squid.sample_time"] {
		t.Error("sample_time must be skipped")
	}
}

func TestChaosTXTRoundTrip(t *testing.T) {
	q := chaosQuery("hits.bind", 7)
	// answer: header (1 answer) + question + compressed name, TXT CH, ttl, rdata "12"
	a := append([]byte{}, q...)
	binary.BigEndian.PutUint16(a[2:], 0x8180)
	binary.BigEndian.PutUint16(a[6:], 1)
	a = append(a, 0xC0, 12, 0, 16, 0, 3, 0, 0, 0, 0, 0, 3, 2, '1', '2')
	v, err := parseChaosTXT(a, 7)
	if err != nil || v != "12" {
		t.Fatalf("%q %v", v, err)
	}
}
