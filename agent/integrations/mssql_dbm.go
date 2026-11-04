package integrations

// SQL Server Database Monitoring run by the agent (track A1), opt-in, the same model as
// postgres_dbm.go:
//
//   - `dbm: true`: per-query_hash series from sys.dm_exec_query_stats deltas every round:
//     mssql.query.{calls,total_time,rows,logical_reads,physical_reads} (agent running totals, so
//     plan-cache eviction does not break rate()) and mssql.query.mean_time; Query Store health of
//     the connected database (state, storage use) and plan regressions (queries with several plans
//     in the last hour, worst/best mean duration) every 10 rounds; blocking chains with statements.
//   - `collect_samples: true`: sys.dm_exec_requests every second into db.activity.sessions and
//     db.query.sample, wait types grouped into categories.
//   - with `collect_samples` and `explain`: the cached plan of sampled statements
//     (sys.dm_exec_query_plan: nothing runs) with literals removed.
//
// Literals are removed from every statement and from showplan attributes that carry them.

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const mssqlStmtText = `SUBSTRING(st.text, %[1]s.statement_start_offset / 2 + 1, (CASE %[1]s.statement_end_offset
	WHEN -1 THEN DATALENGTH(st.text) ELSE %[1]s.statement_end_offset END - %[1]s.statement_start_offset) / 2 + 1)`

func mssqlText(alias string) string { return strings.ReplaceAll(mssqlStmtText, "%[1]s", alias) }

var mssqlQueryStatsSQL = `SELECT CONVERT(varchar(34), qs.query_hash, 1) AS qhash, COALESCE(DB_NAME(pa.dbid), '') AS db,
	SUM(qs.execution_count) AS calls, SUM(qs.total_elapsed_time) / 1000.0 AS total_ms, SUM(qs.total_rows) AS rows_n,
	SUM(qs.total_logical_reads) AS lreads, SUM(qs.total_physical_reads) AS preads,
	MIN(CAST(` + mssqlText("qs") + ` AS nvarchar(1000))) AS q
	FROM sys.dm_exec_query_stats qs
	CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
	CROSS APPLY (SELECT CONVERT(int, value) AS dbid FROM sys.dm_exec_plan_attributes(qs.plan_handle)
		WHERE attribute = 'dbid') pa
	GROUP BY qs.query_hash, pa.dbid`

type mssqlDBMState struct {
	deltas dbm.Deltas
	round  int
}

func collectMSSQLDBM(ctx context.Context, db *sql.DB, st *mssqlDBMState, out sink.Sink, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st.round++
	if rows, err := queryMaps(ctx, db, mssqlQueryStatsSQL); err == nil {
		EmitMSSQLQueryStats(out, &st.deltas, rows, now)
	}
	if st.round%explainEvery == 1 {
		if rows, err := queryMaps(ctx, db, `SELECT actual_state_desc AS state, current_storage_size_mb AS used,
			max_storage_size_mb AS max FROM sys.database_query_store_options`); err == nil {
			EmitMSSQLQueryStore(out, rows, now)
		}
		if rows, err := queryMaps(ctx, db, `SELECT TOP 20 CONVERT(varchar(34), q.query_hash, 1) AS qhash,
			COUNT(DISTINCT p.plan_id) AS plans, MAX(rs.avg_duration) / 1000.0 AS worst_ms,
			MIN(rs.avg_duration) / 1000.0 AS best_ms
			FROM sys.query_store_query q JOIN sys.query_store_plan p ON p.query_id = q.query_id
			JOIN sys.query_store_runtime_stats rs ON rs.plan_id = p.plan_id
			JOIN sys.query_store_runtime_stats_interval i ON i.runtime_stats_interval_id = rs.runtime_stats_interval_id
			WHERE i.start_time > DATEADD(hour, -1, SYSUTCDATETIME())
			GROUP BY q.query_hash HAVING COUNT(DISTINCT p.plan_id) > 1
			ORDER BY MAX(rs.avg_duration) - MIN(rs.avg_duration) DESC`); err == nil {
			EmitMSSQLRegressions(out, rows, now)
		}
	}
	// Blocked requests with the statement of each side (an idle blocker's last statement).
	if rows, err := queryMaps(ctx, db, `SELECT r.session_id AS waiting_pid, r.blocking_session_id AS blocking_pid,
		r.wait_time AS wait_age_secs, COALESCE(CAST(wt.text AS nvarchar(1000)), '') AS wq,
		COALESCE((SELECT TOP 1 CAST(bt.text AS nvarchar(1000)) FROM sys.dm_exec_connections c
			CROSS APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) bt
			WHERE c.session_id = r.blocking_session_id), '') AS bq
		FROM sys.dm_exec_requests r OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) wt
		WHERE r.blocking_session_id <> 0`); err == nil {
		reportBlocking(out, "mssql", rows, 1, now) // wait_time is in ms
	}
}

// EmitMSSQLQueryStats turns one read of the plan-cache statistics into per-query_hash series.
// Statement's block counters carry logical and physical reads.
func EmitMSSQLQueryStats(out sink.Sink, d *dbm.Deltas, rows []map[string]string, now time.Time) {
	st := make([]dbm.Statement, 0, len(rows))
	for _, r := range rows {
		s := dbm.Statement{Database: r["db"], QueryID: r["qhash"], Query: r["q"], Calls: int64(sqlNum(r["calls"])),
			TotalMs: sqlNum(r["total_ms"]), Rows: int64(sqlNum(r["rows_n"])), BlksHit: int64(sqlNum(r["lreads"])),
			BlksRead: int64(sqlNum(r["preads"]))}
		s.Key = s.Database + "/" + s.QueryID
		st = append(st, s)
	}
	for _, s := range d.Observe(st, dbm.MaxStatements) {
		a := map[string]string{"database": s.Database, "query_hash": s.QueryID, "query": dbm.BindSafe(s.Query),
			"db.query.hash": dbm.QueryHash(s.Query, false)}
		out.Sum("mssql.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("mssql.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("mssql.query.rows", "{rows}", float64(s.Rows), a, now)
		out.Sum("mssql.query.logical_reads", "{pages}", float64(s.BlksHit), a, now)
		out.Sum("mssql.query.physical_reads", "{pages}", float64(s.BlksRead), a, now)
		out.Gauge("mssql.query.mean_time", "ms", s.MeanMs, a, now)
	}
}

// EmitMSSQLQueryStore reports Query Store state (1 for the current one) and storage use. A store
// that went READ_ONLY because it is full stops capturing silently.
func EmitMSSQLQueryStore(out sink.Sink, rows []map[string]string, now time.Time) {
	for _, r := range rows {
		out.Gauge("mssql.query_store.state", "1", 1, map[string]string{"state": r["state"]}, now)
		if m := sqlNum(r["max"]); m > 0 {
			out.Gauge("mssql.query_store.storage_utilization", "1", sqlNum(r["used"])/m, nil, now)
		}
	}
}

// EmitMSSQLRegressions reports queries that ran with more than one plan in the last hour.
func EmitMSSQLRegressions(out sink.Sink, rows []map[string]string, now time.Time) {
	for _, r := range rows {
		a := map[string]string{"query_hash": r["qhash"]}
		out.Gauge("mssql.query_store.plans", "{plans}", sqlNum(r["plans"]), a, now)
		if b := sqlNum(r["best_ms"]); b > 0 {
			out.Gauge("mssql.query_store.regression_ratio", "1", sqlNum(r["worst_ms"])/b, a, now)
		}
	}
}

var mssqlSampleSQL = `SELECT COALESCE(DB_NAME(r.database_id), '') AS db, r.status AS state,
	COALESCE(r.wait_type, '') AS wait, CONVERT(varchar(34), r.query_hash, 1) AS qhash,
	COALESCE(CAST(` + mssqlText("r") + ` AS nvarchar(4000)), '') AS q, r.total_elapsed_time AS ms
	FROM sys.dm_exec_requests r JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
	CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) st
	WHERE s.is_user_process = 1 AND r.session_id <> @@SPID`

// mssqlWaitType groups a SQL Server wait type into a category for db.activity.sessions.
func mssqlWaitType(w string) string {
	for _, c := range []struct{ prefix, cat string }{
		{"LCK_", "Lock"}, {"PAGEIOLATCH", "Buffer IO"}, {"PAGELATCH", "Buffer Latch"}, {"LATCH", "Latch"},
		{"WRITELOG", "Tran Log IO"}, {"LOGBUFFER", "Tran Log IO"}, {"CX", "Parallelism"},
		{"ASYNC_NETWORK_IO", "Network IO"}, {"RESOURCE_SEMAPHORE", "Memory"}, {"SOS_SCHEDULER_YIELD", "CPU"},
		{"IO_COMPLETION", "Other Disk IO"}, {"HADR_", "Replication"},
	} {
		if strings.HasPrefix(w, c.prefix) {
			return c.cat
		}
	}
	if w == "" {
		return ""
	}
	return "Other"
}

// MSSQLActivity maps sampled requests.
func MSSQLActivity(rows []map[string]string) []dbm.Activity {
	out := make([]dbm.Activity, 0, len(rows))
	for _, r := range rows {
		out = append(out, dbm.Activity{Database: r["db"], State: r["state"], WaitType: mssqlWaitType(r["wait"]),
			Wait: r["wait"], QueryID: r["qhash"], Query: r["q"], DurationMs: sqlNum(r["ms"])})
	}
	return out
}

func runMSSQLSamples(ctx context.Context, c *MSSQLConfig, out sink.Sink) {
	db, err := sql.Open("sqlserver", c.DSN)
	if err != nil {
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	snap := func(ctx context.Context) ([]dbm.Activity, error) {
		rows, err := queryMaps(ctx, db, mssqlSampleSQL)
		return MSSQLActivity(rows), err
	}
	var explain func(context.Context, sink.Sink, []dbm.Candidate, time.Time)
	if c.Explain {
		var gate explainGate
		explain = func(ctx context.Context, out sink.Sink, cands []dbm.Candidate, now time.Time) {
			for _, cd := range gate.pick(cands, now) {
				if cd.QueryID == "" {
					continue
				}
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				var plan sql.NullString
				err := db.QueryRowContext(cctx, `SELECT TOP 1 CAST(qp.query_plan AS nvarchar(max))
					FROM sys.dm_exec_query_stats qs CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) qp
					WHERE qs.query_hash = CONVERT(binary(8), @p1, 1) AND qp.query_plan IS NOT NULL`, cd.QueryID).Scan(&plan)
				cancel()
				if err == nil && plan.Valid {
					EmitPlan(out, "mssql", cd.QueryID, cd.Query, ScrubShowplan(plan.String), now)
				}
			}
		}
	}
	sampleLoop(ctx, "mssql", out, snap, explain)
}

var reShowplanLiteral = regexp.MustCompile(`\b(StatementText|ScalarString|ConstValue|ParameterCompiledValue|ParameterRuntimeValue)="([^"]*)"`)

// ScrubShowplan removes literals from a showplan XML: the attributes that carry statement text,
// scalar expressions, constants and sniffed parameter values go through BindSafe; costs and row
// estimates are kept.
func ScrubShowplan(plan string) string {
	return reShowplanLiteral.ReplaceAllStringFunc(plan, func(m string) string {
		s := reShowplanLiteral.FindStringSubmatch(m)
		v := strings.NewReplacer("&apos;", "'", "&quot;", `"`).Replace(s[2])
		v = strings.ReplaceAll(dbm.BindSafe(v), `"`, "&quot;")
		return s[1] + `="` + v + `"`
	})
}
