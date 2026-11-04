package integrations

// Native Oracle observability (track A1): with `dsn`, the agent reads Oracle's dynamic performance
// views itself (pure-Go driver, no exporter, no Instant Client). Without `dsn` the module keeps
// scraping oracledb_exporter at `url` (exporter.go). Only views that need no extra-cost option are
// read: v$sysstat, v$system_event, v$session, v$sqlarea, v$sql_plan, dba_tablespace_usage_metrics;
// never v$active_session_history or DBA_HIST_* (Diagnostics Pack). The 1 s v$session sampler is
// the ASH equivalent. The login needs SELECT_CATALOG_ROLE (or SELECT on those views); DSN
// (oracle://user:pass@host:1521/service) is local config only.
//
//   - every round: commits, rollbacks, executions, hard parses, reads and redo; wait time per
//     wait class; sessions by status; tablespace use; blocking chains with statements.
//   - `dbm: true`: per-sql_id series from v$sqlarea deltas (oracle.query.*); with `explain` the
//     cached plans (v$sql_plan, nothing is executed) of the 5 busiest every 10 rounds.
//   - `collect_samples: true`: active user sessions every second (db.activity.sessions,
//     db.query.sample), with `explain` their cached plans.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2" // MIT, pure Go

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// OracleConfig is either the exporter scrape (url) or the native reader (dsn).
type OracleConfig struct {
	ExporterConfig
	DSN            string `json:"dsn"`
	DBM            bool   `json:"dbm"`
	CollectSamples bool   `json:"collect_samples"`
	Explain        bool   `json:"explain"`
}

func (c *OracleConfig) check() error {
	if c.DSN == "" {
		return c.ExporterConfig.check()
	}
	if !strings.HasPrefix(c.DSN, "oracle://") {
		return errors.New("oracle: dsn must be oracle://user:pass@host:1521/service (in the agent's own config file)")
	}
	return nil
}

// Oracle reads Oracle natively when dsn is set, else scrapes oracledb_exporter.
func Oracle(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &OracleConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.DSN == "" {
		return runExporter(ctx, exporterSpec{name: "oracle", prefixes: []string{"oracledb_"}, interval: 30 * time.Second}, raw, out)
	}
	db, err := sql.Open("oracle", c.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if c.CollectSamples && (c.Enabled == nil || *c.Enabled) {
		go runOracleSamples(ctx, c, out)
	}
	var deltas dbm.Deltas
	round := 0
	return Loop(ctx, "oracle", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		round++
		if c.DBM {
			top := collectOracleSQL(ctx, db, &deltas, out, now)
			if c.Explain && round%explainEvery == 1 {
				for i, s := range top {
					if i >= 5 {
						break
					}
					if plan, err := oraclePlan(ctx, db, s.QueryID); err == nil {
						EmitPlan(out, "oracle", s.QueryID, s.Query, plan, now)
					}
				}
			}
		}
		return CollectOracle(ctx, db, out, now)
	})
}

var oracleStats = map[string]string{
	"user commits": "oracle.commits", "user rollbacks": "oracle.rollbacks", "execute count": "oracle.executions",
	"parse count (hard)": "oracle.parses.hard", "parse count (total)": "oracle.parses.total",
	"physical reads": "oracle.physical_reads", "session logical reads": "oracle.logical_reads",
	"redo size": "oracle.redo_size", "user calls": "oracle.user_calls",
}

// CollectOracle runs one round of the always-on views.
func CollectOracle(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := queryMaps(ctx, db, `SELECT name AS n, value AS v FROM v$sysstat WHERE name IN ('user commits',
		'user rollbacks', 'execute count', 'parse count (hard)', 'parse count (total)', 'physical reads',
		'session logical reads', 'redo size', 'user calls')`)
	if err != nil {
		return err
	}
	EmitOracleRound(out, rows, "stat", now)
	if r, err := queryMaps(ctx, db, `SELECT wait_class AS c, SUM(time_waited_micro) / 1000 AS ms, SUM(total_waits) AS n
		FROM v$system_event WHERE wait_class <> 'Idle' GROUP BY wait_class`); err == nil {
		EmitOracleRound(out, r, "wait", now)
	}
	if r, err := queryMaps(ctx, db, `SELECT status AS s, type AS t, COUNT(*) AS n FROM v$session GROUP BY status, type`); err == nil {
		EmitOracleRound(out, r, "session", now)
	}
	if r, err := queryMaps(ctx, db, `SELECT tablespace_name AS ts, used_percent AS p FROM dba_tablespace_usage_metrics`); err == nil {
		EmitOracleRound(out, r, "tablespace", now)
	}
	if r, err := queryMaps(ctx, db, `SELECT s.sid AS waiting_pid, s.blocking_session AS blocking_pid,
		s.wait_time_micro / 1000000 AS wait_age_secs, SUBSTR(w.sql_text, 1, 1000) AS wq, SUBSTR(b.sql_text, 1, 1000) AS bq
		FROM v$session s LEFT JOIN v$sqlarea w ON w.sql_id = s.sql_id
		LEFT JOIN v$session bs ON bs.sid = s.blocking_session
		LEFT JOIN v$sqlarea b ON b.sql_id = COALESCE(bs.sql_id, bs.prev_sql_id)
		WHERE s.blocking_session IS NOT NULL AND s.state = 'WAITING'`); err == nil {
		reportBlocking(out, "oracle", r, 1000, now)
	}
	return nil
}

// EmitOracleRound maps one view's rows (kind stat, wait, session or tablespace).
func EmitOracleRound(out sink.Sink, rows []map[string]string, kind string, now time.Time) {
	for _, r := range rows {
		switch kind {
		case "stat":
			if n, ok := oracleStats[r["n"]]; ok {
				out.Sum(n, "1", sqlNum(r["v"]), nil, now)
			}
		case "wait":
			a := map[string]string{"wait_class": r["c"]}
			out.Sum("oracle.wait.time", "ms", sqlNum(r["ms"]), a, now)
			out.Sum("oracle.wait.count", "{waits}", sqlNum(r["n"]), a, now)
		case "session":
			out.Gauge("oracle.sessions", "{sessions}", sqlNum(r["n"]), map[string]string{"status": r["s"], "type": r["t"]}, now)
		case "tablespace":
			out.Gauge("oracle.tablespace.used_percent", "%", sqlNum(r["p"]), map[string]string{"tablespace": r["ts"]}, now)
		}
	}
}

// collectOracleSQL emits the per-sql_id series and returns them busiest first.
func collectOracleSQL(ctx context.Context, db *sql.DB, d *dbm.Deltas, out sink.Sink, now time.Time) []dbm.StatementDelta {
	rows, err := queryMaps(ctx, db, `SELECT * FROM (SELECT parsing_schema_name AS db, sql_id AS id,
		executions AS calls, elapsed_time / 1000 AS total_ms, rows_processed AS rows_n, buffer_gets AS gets,
		disk_reads AS reads, SUBSTR(sql_text, 1, 1000) AS q FROM v$sqlarea
		WHERE parsing_schema_name NOT IN ('SYS', 'SYSTEM') AND executions > 0 ORDER BY elapsed_time DESC)
		WHERE ROWNUM <= 5000`)
	if err != nil {
		return nil
	}
	return EmitOracleSQL(out, d, rows, now)
}

// EmitOracleSQL turns one read of v$sqlarea into per-sql_id series. Statement's block counters
// carry buffer gets and disk reads.
func EmitOracleSQL(out sink.Sink, d *dbm.Deltas, rows []map[string]string, now time.Time) []dbm.StatementDelta {
	st := make([]dbm.Statement, 0, len(rows))
	for _, r := range rows {
		s := dbm.Statement{Database: r["db"], QueryID: r["id"], Query: r["q"], Calls: int64(sqlNum(r["calls"])),
			TotalMs: sqlNum(r["total_ms"]), Rows: int64(sqlNum(r["rows_n"])), BlksHit: int64(sqlNum(r["gets"])),
			BlksRead: int64(sqlNum(r["reads"]))}
		s.Key = s.Database + "/" + s.QueryID
		st = append(st, s)
	}
	top := d.Observe(st, dbm.MaxStatements)
	for _, s := range top {
		a := map[string]string{"database": s.Database, "sql_id": s.QueryID, "query": dbm.BindSafe(s.Query),
			"db.query.hash": dbm.QueryHash(s.Query, false)}
		out.Sum("oracle.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("oracle.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("oracle.query.rows", "{rows}", float64(s.Rows), a, now)
		out.Sum("oracle.query.buffer_gets", "{blocks}", float64(s.BlksHit), a, now)
		out.Sum("oracle.query.disk_reads", "{blocks}", float64(s.BlksRead), a, now)
		out.Gauge("oracle.query.mean_time", "ms", s.MeanMs, a, now)
	}
	return top
}

const oracleSampleSQL = `SELECT s.schemaname AS db, s.status AS state,
	CASE WHEN s.state = 'WAITING' THEN s.wait_class END AS wclass, CASE WHEN s.state = 'WAITING' THEN s.event END AS wait,
	s.sql_id AS sqlid, SUBSTR(q.sql_text, 1, 1000) AS q, s.last_call_et * 1000 AS ms
	FROM v$session s LEFT JOIN v$sqlarea q ON q.sql_id = s.sql_id
	WHERE s.type = 'USER' AND s.status = 'ACTIVE' AND s.sid <> SYS_CONTEXT('USERENV', 'SID')
	AND NOT (s.state = 'WAITING' AND s.wait_class = 'Idle')`

// OracleActivity maps sampled sessions; a session not waiting is on CPU.
func OracleActivity(rows []map[string]string) []dbm.Activity {
	out := make([]dbm.Activity, 0, len(rows))
	for _, r := range rows {
		out = append(out, dbm.Activity{Database: r["db"], State: strings.ToLower(r["state"]), WaitType: r["wclass"],
			Wait: r["wait"], QueryID: r["sqlid"], Query: r["q"], DurationMs: sqlNum(r["ms"])})
	}
	return out
}

func runOracleSamples(ctx context.Context, c *OracleConfig, out sink.Sink) {
	db, err := sql.Open("oracle", c.DSN)
	if err != nil {
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	snap := func(ctx context.Context) ([]dbm.Activity, error) {
		rows, err := queryMaps(ctx, db, oracleSampleSQL)
		return OracleActivity(rows), err
	}
	var explain func(context.Context, sink.Sink, []dbm.Candidate, time.Time)
	if c.Explain {
		var gate explainGate
		explain = func(ctx context.Context, out sink.Sink, cands []dbm.Candidate, now time.Time) {
			for _, cd := range gate.pick(cands, now) {
				if plan, err := oraclePlan(ctx, db, cd.QueryID); err == nil {
					EmitPlan(out, "oracle", cd.QueryID, cd.Query, plan, now)
				}
			}
		}
	}
	sampleLoop(ctx, "oracle", out, snap, explain)
}

// oraclePlan reads the cached plan of a sql_id's first child cursor from v$sql_plan.
func oraclePlan(ctx context.Context, db *sql.DB, sqlID string) (string, error) {
	if sqlID == "" {
		return "", errors.New("oracle: no sql_id")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT id, COALESCE(parent_id, -1), operation || ' ' || options, object_owner || '.' || object_name,
		COALESCE(cost, 0), COALESCE(cardinality, 0), access_predicates, filter_predicates FROM v$sql_plan
		WHERE sql_id = :1 AND child_number = (SELECT MIN(child_number) FROM v$sql_plan WHERE sql_id = :2) ORDER BY id`, sqlID, sqlID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var steps []OraclePlanStep
	for rows.Next() {
		var s OraclePlanStep
		var obj, acc, filt sql.NullString
		if err := rows.Scan(&s.ID, &s.Parent, &s.Operation, &obj, &s.Cost, &s.Rows, &acc, &filt); err != nil {
			return "", err
		}
		s.Object, s.Access, s.Filter = strings.Trim(obj.String, "."), acc.String, filt.String
		steps = append(steps, s)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return OraclePlanJSON(steps)
}

// OraclePlanStep is one v$sql_plan row.
type OraclePlanStep struct {
	ID, Parent     int
	Operation      string
	Object         string
	Cost, Rows     float64
	Access, Filter string
}

// OraclePlanJSON builds the plan tree in the same JSON shape as a PostgreSQL plan ("Node Type",
// "Total Cost", "Plans"), so the plan views and EmitPlan read every engine alike, and removes
// the literals from its predicates.
func OraclePlanJSON(steps []OraclePlanStep) (string, error) {
	if len(steps) == 0 {
		return "", errors.New("oracle: no plan")
	}
	nodes := map[int]map[string]any{}
	for _, s := range steps {
		n := map[string]any{"Node Type": strings.TrimSpace(s.Operation), "Total Cost": s.Cost, "Plan Rows": s.Rows}
		if s.Object != "" {
			n["Relation Name"] = s.Object
		}
		if s.Access != "" {
			n["Index Cond"] = s.Access
		}
		if s.Filter != "" {
			n["Filter"] = s.Filter
		}
		nodes[s.ID] = n
	}
	root := nodes[steps[0].ID]
	for _, s := range steps[1:] {
		if p, ok := nodes[s.Parent]; ok {
			kids, _ := p["Plans"].([]any)
			p["Plans"] = append(kids, nodes[s.ID])
		}
	}
	b, err := json.Marshal([]map[string]any{{"Plan": root}})
	if err != nil {
		return "", err
	}
	if p := dbm.ObfuscatePlan(string(b)); p != "" {
		return p, nil
	}
	return "", errors.New("oracle: plan did not encode")
}
