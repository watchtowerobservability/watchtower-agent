package integrations

// YugabyteDB YSQL (track A1) over the PostgreSQL protocol, no exporter. Every round: tablet
// servers (yb_servers(): connections per node) and the tablets of the connected node by table
// and state (yb_local_tablets, 2.21+). `dbm: true` adds per-queryid series from
// pg_stat_statements (on by default in YugabyteDB; total_time before the PG15 base,
// total_exec_time after) and the node's Active Session History (yb_active_session_history, 2.20+
// with ysql_yb_enable_ash; free, unlike Oracle's) as db.activity.sessions by wait class and event.
// The views are per node: point one module at each tserver to cover a universe.

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

type ybState struct {
	deltas  dbm.Deltas
	ashFrom time.Time // newest ASH sample already counted
}

// YugabyteDB collects one YugabyteDB node.
func YugabyteDB(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &DistSQLConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	db, err := pgReadOnlyDB(c.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	st := &ybState{}
	return Loop(ctx, "yugabytedb", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		if c.DBM {
			collectYBDBM(ctx, db, st, out, now)
		}
		return CollectYugabyteDB(ctx, db, out, now)
	})
}

// CollectYugabyteDB reads servers and local tablets.
func CollectYugabyteDB(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	servers, err := queryMaps(ctx, db, `SELECT host, num_connections AS conns, node_type AS type,
		COALESCE(region, '') AS region, COALESCE(zone, '') AS zone FROM yb_servers()`)
	if err != nil {
		return err
	}
	EmitYB(out, "servers", servers, now)
	if r, err := queryMaps(ctx, db, `SELECT namespace_name AS db, table_name AS t, state, count(*) AS n
		FROM yb_local_tablets GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 500`); err == nil {
		EmitYB(out, "tablets", r, now)
	}
	return nil
}

// EmitYB maps rows of kind servers or tablets.
func EmitYB(out sink.Sink, kind string, rows []map[string]string, now time.Time) {
	if kind == "servers" {
		out.Gauge("yugabytedb.servers", "{servers}", float64(len(rows)), nil, now)
	}
	for _, r := range rows {
		switch kind {
		case "servers":
			out.Gauge("yugabytedb.server.connections", "{connections}", sqlNum(r["conns"]), map[string]string{
				"server": r["host"], "node_type": r["type"], "region": r["region"], "zone": r["zone"]}, now)
		case "tablets":
			out.Gauge("yugabytedb.tablets", "{tablets}", sqlNum(r["n"]), map[string]string{
				"database": r["db"], "table": r["t"], "state": r["state"]}, now)
		}
	}
}

func collectYBDBM(ctx context.Context, db *sql.DB, st *ybState, out sink.Sink, now time.Time) {
	var ver int
	if err := db.QueryRowContext(ctx, "SELECT current_setting('server_version_num')::int").Scan(&ver); err != nil {
		return
	}
	total := "total_time"
	if ver >= 130000 {
		total = "total_exec_time"
	}
	if rows, err := queryMaps(ctx, db, `SELECT d.datname AS db, s.queryid::text AS id, left(min(s.query), 1000) AS q,
		sum(s.calls) AS calls, sum(s.`+total+`) AS total_ms, sum(s.rows) AS rows_n,
		sum(s.shared_blks_hit) AS hit, sum(s.shared_blks_read) AS rd
		FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid WHERE s.queryid IS NOT NULL
		GROUP BY 1, 2`); err == nil {
		EmitYBStatements(out, &st.deltas, rows, now)
	}
	from := st.ashFrom
	if from.IsZero() || now.Sub(from) > 5*time.Minute {
		from = now.Add(-30 * time.Second)
	}
	if rows, err := queryMaps(ctx, db, `SELECT COALESCE(d.datname, '') AS db, a.wait_event_class AS class,
		a.wait_event AS event, count(*) AS n, max(a.sample_time) AS newest
		FROM yb_active_session_history a LEFT JOIN pg_database d ON d.oid = a.ysql_dbid
		WHERE a.sample_time > $1 GROUP BY 1, 2, 3`, from); err == nil {
		if newest := EmitYBASH(out, rows, now.Sub(from), now); !newest.IsZero() {
			st.ashFrom = newest
		}
	}
}

// EmitYBStatements turns one read of pg_stat_statements into per-queryid series.
func EmitYBStatements(out sink.Sink, d *dbm.Deltas, rows []map[string]string, now time.Time) {
	st := make([]dbm.Statement, 0, len(rows))
	for _, r := range rows {
		s := dbm.Statement{Database: r["db"], QueryID: r["id"], Query: r["q"], Calls: int64(sqlNum(r["calls"])),
			TotalMs: sqlNum(r["total_ms"]), Rows: int64(sqlNum(r["rows_n"])), BlksHit: int64(sqlNum(r["hit"])),
			BlksRead: int64(sqlNum(r["rd"]))}
		s.Key = s.Database + "/" + s.QueryID
		st = append(st, s)
	}
	for _, s := range d.Observe(st, dbm.MaxStatements) {
		// pg_stat_statements text has $n placeholders, which normalize like the literals of a span.
		a := map[string]string{"database": s.Database, "queryid": s.QueryID, "query": dbm.BindSafe(s.Query),
			"db.query.hash": dbm.QueryHash(s.Query, true)}
		out.Sum("yugabytedb.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("yugabytedb.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("yugabytedb.query.rows", "{rows}", float64(s.Rows), a, now)
		out.Gauge("yugabytedb.query.mean_time", "ms", s.MeanMs, a, now)
	}
}

// EmitYBASH turns ASH sample counts over window into average sessions (ASH samples once a second)
// and returns the newest sample time seen.
func EmitYBASH(out sink.Sink, rows []map[string]string, window time.Duration, now time.Time) time.Time {
	var newest time.Time
	secs := max(window.Seconds(), 1)
	for _, r := range rows {
		out.Gauge("db.activity.sessions", "{sessions}", sqlNum(r["n"])/secs, map[string]string{
			"db.system.name": "yugabytedb", "db.namespace": r["db"], "db.session.state": "active",
			"db.wait_event_type": orCPUWait(r["class"]), "db.wait_event": orCPUWait(r["event"]),
		}, now)
		if t, err := time.Parse(time.RFC3339Nano, r["newest"]); err == nil && t.After(newest) {
			newest = t
		}
	}
	return newest
}

func orCPUWait(s string) string {
	if s == "" {
		return "CPU"
	}
	return s
}
