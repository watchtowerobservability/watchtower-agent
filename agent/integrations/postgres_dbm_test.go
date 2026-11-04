package integrations

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The agent hashes pg_stat_statements' already-masked text ($N); the span side hashes the raw
// statement with real literals. W36 only joins if both land on the same db.query.hash.
func TestPostgresQueryHashJoinsSpans(t *testing.T) {
	agent := dbm.QueryHash("SELECT * FROM users WHERE id = $1 AND org = $2", true)
	span := dbm.QueryHash("SELECT * FROM users WHERE id = 42 AND org = 'acme'", true)
	if agent != span || agent == "" {
		t.Fatalf("agent %q != span %q", agent, span)
	}
}

// A plan emitted through the sampling path's hashSink carries db.query.hash of the raw statement.
func TestExplainPlanStampsQueryHash(t *testing.T) {
	raw := "SELECT * FROM orders WHERE total > 100"
	var r sink.Recorder
	hs := &hashSink{Sink: &r, pg: true, raw: map[string]string{dbm.BindSafe(raw): raw}}
	EmitPlan(hs, "postgresql", "123", dbm.BindSafe(raw), `[{"Plan":{"Node Type":"Seq Scan","Total Cost":9.1}}]`, time.Now())
	if len(r.Samples) != 1 || r.Samples[0].Attrs["db.query.hash"] != dbm.QueryHash(raw, true) {
		t.Fatalf("plan attrs: %+v", r.Samples)
	}
}
