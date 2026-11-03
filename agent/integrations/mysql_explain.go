package integrations

// MySQL EXPLAIN (CFT-A14 depth): every `explainEvery` rounds, EXPLAIN FORMAT=JSON the slowest
// recent statements. Their text (with literals) comes from performance_schema.events_statements_
// history_long, which keeps SQL_TEXT per sampled statement; the digest summary has none. Nothing
// is executed: EXPLAIN alone never runs the statement (no ANALYZE in MySQL). The session is
// read-only with a 2 s timeout, and only SELECT/WITH statements are explained.

import (
	"context"
	"database/sql"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// CollectMySQLPlans explains the top recent SELECTs.
func CollectMySQLPlans(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	rows, err := queryMaps(ctx, db, `SELECT DIGEST AS digest, SQL_TEXT AS q, TIMER_WAIT AS t
		FROM performance_schema.events_statements_history_long
		WHERE SQL_TEXT IS NOT NULL AND CURRENT_SCHEMA IS NOT NULL
		ORDER BY TIMER_WAIT DESC LIMIT 200`)
	if err != nil {
		return nil // history_long off or not granted
	}
	seen := map[string]bool{}
	done := 0
	for _, r := range rows {
		q := r["q"]
		if done >= 10 || seen[r["digest"]] || !explainable(q) {
			continue
		}
		seen[r["digest"]] = true
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		var typ, plan string
		// A read-only session makes a writing statement that slipped through fail instead of run.
		_, _ = db.ExecContext(cctx, "SET SESSION TRANSACTION READ ONLY, max_execution_time = 2000")
		row := db.QueryRowContext(cctx, "EXPLAIN FORMAT=JSON "+q)
		if err := row.Scan(&typ); err == nil {
			plan = typ
		} else if err := row.Scan(&plan); err != nil { // single-column result
			cancel()
			continue
		}
		cancel()
		EmitPlan(out, "mysql", r["digest"], q, plan, now)
		done++
	}
	return nil
}
