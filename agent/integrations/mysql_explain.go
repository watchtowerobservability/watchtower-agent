package integrations

// MySQL EXPLAIN (CFT-A14 depth): every `explainEvery` rounds, EXPLAIN FORMAT=JSON the slowest
// recent statements. Their text (with literals) comes from performance_schema.events_statements_
// history_long, which keeps SQL_TEXT per sampled statement; the digest summary has none. With
// `collect_samples`, statements sampled from events_statements_current are explained the same
// way (mysql_dbm.go). Nothing is executed: EXPLAIN alone never runs the statement (no ANALYZE).
// The session is read-only with a 2 s timeout, only SELECT/WITH statements are explained, and
// every string in the plan is made bind-safe before it leaves the agent.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// CollectMySQLPlans explains the top recent SELECTs.
func CollectMySQLPlans(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	rows, err := queryMaps(ctx, db, `SELECT DIGEST AS digest, SQL_TEXT AS q, CURRENT_SCHEMA AS db
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
		plan, err := explainMySQL(ctx, db, r["db"], q)
		if err != nil {
			continue
		}
		EmitPlan(out, "mysql", r["digest"], q, plan, now)
		done++
	}
	return nil
}

// explainMySQL plans q in schema on one pinned, read-only connection and returns the bind-safe
// JSON plan.
func explainMySQL(ctx context.Context, db *sql.DB, schema, q string) (string, error) {
	return explainMySQLAs(ctx, db, schema, "EXPLAIN FORMAT=JSON ", q, true)
}

// explainMySQLAs runs explain+q. readOnly is false for TiDB, which refuses SET TRANSACTION READ
// ONLY unless noop functions are on; its EXPLAIN (without ANALYZE) executes nothing either.
func explainMySQLAs(ctx context.Context, db *sql.DB, schema, explain, q string, readOnly bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if schema != "" {
		if _, err := conn.ExecContext(ctx, "USE `"+strings.ReplaceAll(schema, "`", "``")+"`"); err != nil {
			return "", err
		}
	}
	// A read-only session makes a writing statement that slipped through fail instead of run.
	if readOnly {
		if _, err := conn.ExecContext(ctx, "SET SESSION TRANSACTION READ ONLY"); err != nil {
			return "", err
		}
	}
	// max_execution_time is MySQL's name, max_statement_time (seconds) MariaDB's.
	if _, err := conn.ExecContext(ctx, "SET SESSION max_execution_time = 2000"); err != nil {
		_, _ = conn.ExecContext(ctx, "SET SESSION max_statement_time = 2")
	}
	var plan string
	if err := conn.QueryRowContext(ctx, explain+q).Scan(&plan); err != nil {
		return "", err
	}
	if p := dbm.ObfuscatePlan(plan); p != "" {
		return p, nil
	}
	return "", errors.New("mysql: plan is not JSON")
}
