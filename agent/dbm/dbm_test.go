package dbm

import (
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestBlockingChainBuilt(t *testing.T) {
	// 1 blocks 2 and 3; 3 blocks 4. 9 and 8 block each other.
	chains := BuildChains([]Session{
		{PID: 1, Query: "UPDATE t SET a = 5 WHERE id = 7"},
		{PID: 2, BlockedBy: []int{1}},
		{PID: 3, BlockedBy: []int{1}},
		{PID: 4, BlockedBy: []int{3}},
		{PID: 8, BlockedBy: []int{9}},
		{PID: 9, BlockedBy: []int{8}},
	})
	if len(chains) != 2 || chains[0].Root.PID != 1 || len(chains[0].Waiters) != 3 || chains[0].Depth != 2 {
		t.Fatalf("chains = %+v", chains)
	}
	if chains[1].Root.PID != 8 || chains[1].Depth != 2 {
		t.Fatalf("cycle = %+v", chains[1])
	}
}

func TestBindSafeStripsValues(t *testing.T) {
	got := BindSafe("SELECT * FROM u WHERE email = 'a''b@x.io' AND id = 42 AND t2.c = $$secret$$ AND x = 3.5")
	if strings.Contains(got, "@") || strings.Contains(got, "42") || strings.Contains(got, "3.5") || strings.Contains(got, "secret") || !strings.Contains(got, "t2.c") {
		t.Fatalf("leaks a value or damages an identifier: %q", got)
	}
}

func TestReportEmitsGaugesAndChainLogs(t *testing.T) {
	var r sink.Recorder
	Report(&r, "postgresql", []Session{{PID: 1, Query: "select 1"}, {PID: 2, BlockedBy: []int{1}}}, time.Now())
	if !r.Names()["db.sessions.blocked"] || !r.Names()["db.blocking.chain_depth"] {
		t.Fatal("gauges missing")
	}
	logs := 0
	for _, s := range r.Snapshot() {
		if s.Body != "" {
			logs++
		}
	}
	if logs != 1 {
		t.Fatalf("logs = %d", logs)
	}
}
