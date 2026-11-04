package integrations

// CockroachDB (track A1): a read-only SQL session reads crdb_internal, no exporter and no DB
// Console scrape. Every round: nodes live/total, per-store ranges, unavailable and
// under-replicated ranges, capacity, and contention per table. `dbm: true` adds per-fingerprint
// statement series from crdb_internal.cluster_statement_statistics (the in-memory stats of every
// node; they reset when flushed to system tables, which the deltas treat as a counter reset),
// and with `explain` the sampled plan CockroachDB keeps per fingerprint, made bind-safe, for the
// 5 busiest every 10 rounds. The user needs the VIEWACTIVITY (or VIEWACTIVITYREDACTED) privilege.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// DistSQLConfig is the config of the cockroachdb and yugabytedb modules (PostgreSQL wire).
type DistSQLConfig struct {
	Base
	DSN     string `json:"dsn"` // postgres://user:pass@host:26257/defaultdb?sslmode=verify-full
	DBM     bool   `json:"dbm"`
	Explain bool   `json:"explain"`
}

func (c *DistSQLConfig) check() error {
	if !strings.HasPrefix(c.DSN, "postgres://") && !strings.HasPrefix(c.DSN, "postgresql://") {
		return errors.New("dsn (postgres://...) is required (in the agent's own config file)")
	}
	return nil
}

// pgReadOnlyDB opens a database/sql pool of one read-only connection over pgx.
func pgReadOnlyDB(dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "5000"
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(1)
	return db, nil
}

// CockroachDB collects cluster health and statement statistics.
func CockroachDB(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &DistSQLConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	db, err := pgReadOnlyDB(c.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	var deltas dbm.Deltas
	round := 0
	return Loop(ctx, "cockroachdb", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		round++
		if c.DBM {
			if rows, err := queryMaps(ctx, db, crdbStatementsSQL); err == nil {
				top := EmitCRDBStatements(out, &deltas, rows, now)
				if c.Explain && round%explainEvery == 1 {
					crdbPlans(ctx, db, top, out, now)
				}
			}
		}
		return CollectCockroachDB(ctx, db, out, now)
	})
}

// CollectCockroachDB reads liveness, stores and contended tables.
func CollectCockroachDB(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	nodes, err := queryMaps(ctx, db, `SELECT count(*) FILTER (WHERE is_live) AS live, count(*) AS total
		FROM crdb_internal.gossip_nodes`)
	if err != nil {
		return err
	}
	EmitCRDB(out, "nodes", nodes, now)
	if r, err := queryMaps(ctx, db, `SELECT node_id::STRING AS node, store_id::STRING AS store,
		(metrics->>'ranges')::FLOAT8 AS ranges, (metrics->>'ranges.unavailable')::FLOAT8 AS unavailable,
		(metrics->>'ranges.underreplicated')::FLOAT8 AS underreplicated, (metrics->>'replicas.leaseholders')::FLOAT8 AS leases,
		(metrics->>'capacity')::FLOAT8 AS capacity, (metrics->>'capacity.available')::FLOAT8 AS available
		FROM crdb_internal.kv_store_status`); err == nil {
		EmitCRDB(out, "stores", r, now)
	}
	if r, err := queryMaps(ctx, db, `SELECT database_name AS db, schema_name || '.' || table_name AS t,
		num_contention_events AS n FROM crdb_internal.cluster_contended_tables
		ORDER BY num_contention_events DESC LIMIT 100`); err == nil {
		EmitCRDB(out, "contention", r, now)
	}
	return nil
}

// EmitCRDB maps one view's rows (kind nodes, stores or contention).
func EmitCRDB(out sink.Sink, kind string, rows []map[string]string, now time.Time) {
	for _, r := range rows {
		switch kind {
		case "nodes":
			out.Gauge("cockroachdb.nodes.live", "{nodes}", sqlNum(r["live"]), nil, now)
			out.Gauge("cockroachdb.nodes.total", "{nodes}", sqlNum(r["total"]), nil, now)
		case "stores":
			a := map[string]string{"node_id": r["node"], "store_id": r["store"]}
			out.Gauge("cockroachdb.ranges", "{ranges}", sqlNum(r["ranges"]), a, now)
			out.Gauge("cockroachdb.ranges.unavailable", "{ranges}", sqlNum(r["unavailable"]), a, now)
			out.Gauge("cockroachdb.ranges.underreplicated", "{ranges}", sqlNum(r["underreplicated"]), a, now)
			out.Gauge("cockroachdb.leaseholders", "{replicas}", sqlNum(r["leases"]), a, now)
			if cp := sqlNum(r["capacity"]); cp > 0 {
				out.Gauge("cockroachdb.capacity.utilization", "1", 1-sqlNum(r["available"])/cp, a, now)
			}
		case "contention":
			out.Sum("cockroachdb.contention.events", "{events}", sqlNum(r["n"]), map[string]string{"database": r["db"], "table": r["t"]}, now)
		}
	}
}

const crdbStatementsSQL = `SELECT encode(fingerprint_id, 'hex') AS id, COALESCE(metadata->>'db', '') AS db,
	max(metadata->>'query') AS q, sum((statistics->'statistics'->>'cnt')::INT8) AS calls,
	sum((statistics->'statistics'->>'cnt')::FLOAT8 * (statistics->'statistics'->'svcLat'->>'mean')::FLOAT8) * 1000 AS total_ms,
	sum((statistics->'statistics'->>'cnt')::FLOAT8 * (statistics->'statistics'->'numRows'->>'mean')::FLOAT8) AS rows_n,
	sum((statistics->'statistics'->>'cnt')::FLOAT8 * COALESCE((statistics->'statistics'->'rowsRead'->>'mean')::FLOAT8, 0)) AS rows_read
	FROM crdb_internal.cluster_statement_statistics GROUP BY 1, 2`

// EmitCRDBStatements turns one read of the statement statistics into per-fingerprint series.
// Statement's BlksHit carries rows read.
func EmitCRDBStatements(out sink.Sink, d *dbm.Deltas, rows []map[string]string, now time.Time) []dbm.StatementDelta {
	st := make([]dbm.Statement, 0, len(rows))
	for _, r := range rows {
		s := dbm.Statement{Database: r["db"], QueryID: r["id"], Query: r["q"], Calls: int64(sqlNum(r["calls"])),
			TotalMs: sqlNum(r["total_ms"]), Rows: int64(sqlNum(r["rows_n"])), BlksHit: int64(sqlNum(r["rows_read"]))}
		s.Key = s.Database + "/" + s.QueryID
		st = append(st, s)
	}
	top := d.Observe(st, dbm.MaxStatements)
	for _, s := range top {
		a := map[string]string{"database": s.Database, "fingerprint_id": s.QueryID, "query": dbm.BindSafe(s.Query)}
		out.Sum("cockroachdb.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("cockroachdb.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("cockroachdb.query.rows", "{rows}", float64(s.Rows), a, now)
		out.Sum("cockroachdb.query.rows_read", "{rows}", float64(s.BlksHit), a, now)
		out.Gauge("cockroachdb.query.mean_time", "ms", s.MeanMs, a, now)
	}
	return top
}

// crdbPlans logs the sampled plan of the 5 busiest fingerprints.
func crdbPlans(ctx context.Context, db *sql.DB, top []dbm.StatementDelta, out sink.Sink, now time.Time) {
	for i, s := range top {
		if i >= 5 {
			return
		}
		var plan sql.NullString
		err := db.QueryRowContext(ctx, `SELECT sampled_plan::STRING FROM crdb_internal.cluster_statement_statistics
			WHERE encode(fingerprint_id, 'hex') = $1 AND sampled_plan IS NOT NULL LIMIT 1`, s.QueryID).Scan(&plan)
		if err != nil || !plan.Valid {
			continue
		}
		if p := dbm.ObfuscatePlan(plan.String); p != "" && p != "{}" {
			EmitPlan(out, "cockroachdb", s.QueryID, s.Query, p, now)
		}
	}
}
