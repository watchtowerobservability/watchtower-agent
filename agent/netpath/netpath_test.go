package netpath

import (
	"context"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func fake(_ context.Context, _ string, _, _ int) (string, int, bool, string) {
	return `[{"ttl":1}]`, 3, true, ""
}

func TestOnceEmitsPathAsPrivateProbe(t *testing.T) {
	var rec sink.Recorder
	Once(context.Background(), fake, []Target{{Name: "db", Host: "10.0.0.5"}}, &rec, time.Now())
	names := rec.Names()
	if !names["wt_path_up"] || !names["wt_path_hops"] {
		t.Fatalf("metrics %v", names)
	}
	var logs int
	for _, s := range rec.Samples {
		if s.Attrs["event.name"] == "network.path" && s.Attrs["path.reached"] == "true" && s.Body == `[{"ttl":1}]` {
			logs++
		}
	}
	if logs != 1 {
		t.Fatalf("log records: %d", logs)
	}
}
