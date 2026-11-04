package integrations

// Native SQL Server observability (CFT-A14, database_observability.sql_server parity): a
// read-only connection to SQL Server reads performance counters, wait statistics, the top query
// plans and a schema snapshot through the DMVs, with no exporter sidecar. DSN is local config
// only (it carries the password). The login needs VIEW SERVER STATE and VIEW DATABASE STATE.
//
// This replaces the exporter-scrape MSSQL in exporter.go; the module name stays `mssql`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// parseF parses a DMV numeric cell; blank or NULL is an error so no point is emitted.
func parseF(s string) (float64, error) { return strconv.ParseFloat(strings.TrimSpace(s), 64) }

// MSSQLConfig is the module config. ApplicationIntent=ReadOnly is forced on the connection.
type MSSQLConfig struct {
	Base
	DSN     string `json:"dsn"` // sqlserver://user:pass@host:1433?database=master
	Explain bool   `json:"explain"`
	Schema  bool   `json:"schema"`
	// Database Monitoring (mssql_dbm.go).
	DBM            bool `json:"dbm"`
	CollectSamples bool `json:"collect_samples"`
}

func (c *MSSQLConfig) check() error {
	if !strings.HasPrefix(c.DSN, "sqlserver://") && !strings.Contains(c.DSN, "server=") {
		return errors.New("mssql: dsn is required (sqlserver://... , in the agent's own config file)")
	}
	return nil
}

// MSSQL collects from SQL Server through the DMVs.
func MSSQL(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &MSSQLConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	db, err := sql.Open("sqlserver", c.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if c.CollectSamples && (c.Enabled == nil || *c.Enabled) {
		go runMSSQLSamples(ctx, c, out)
	}
	var st mssqlDBMState
	round := 0
	return Loop(ctx, "mssql", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		round++
		if c.DBM {
			collectMSSQLDBM(ctx, db, &st, out, now)
		}
		if c.Schema && round%schemaEvery == 1 {
			_ = CollectMSSQLSchema(ctx, db, out, now)
		}
		if c.Explain && round%explainEvery == 1 {
			_ = CollectMSSQLPlans(ctx, db, out, now)
		}
		return CollectMSSQL(ctx, db, out, now)
	})
}

// CollectMSSQL reads performance counters, wait stats and blocking sessions.
func CollectMSSQL(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Cumulative performance counters (cntr_type 272696576 and 65792 are the useful ones).
	counters, err := queryMaps(ctx, db, `SELECT RTRIM(object_name) AS obj, RTRIM(counter_name) AS ctr,
		RTRIM(COALESCE(instance_name,'')) AS inst, cntr_value AS v
		FROM sys.dm_os_performance_counters WHERE cntr_type IN (272696576, 65792)`)
	if err != nil {
		return err
	}
	for _, r := range counters {
		f, err := parseF(r["v"])
		if err != nil {
			continue
		}
		a := map[string]string{"counter": r["ctr"], "object": r["obj"]}
		if r["inst"] != "" {
			a["instance"] = r["inst"]
		}
		out.Sum("mssql.performance_counter", "1", f, a, now)
	}
	// Top wait categories by accumulated wait time.
	if waits, err := queryMaps(ctx, db, `SELECT TOP 25 wait_type, wait_time_ms, waiting_tasks_count
		FROM sys.dm_os_wait_stats WHERE wait_time_ms > 0
		AND wait_type NOT LIKE '%SLEEP%' AND wait_type NOT LIKE 'XE%' AND wait_type NOT LIKE 'BROKER%'
		ORDER BY wait_time_ms DESC`); err == nil {
		for _, r := range waits {
			a := map[string]string{"wait_type": r["wait_type"]}
			if ms, err := parseF(r["wait_time_ms"]); err == nil {
				out.Sum("mssql.wait.time", "ms", ms, a, now)
			}
			if n, err := parseF(r["waiting_tasks_count"]); err == nil {
				out.Sum("mssql.wait.tasks", "{tasks}", n, a, now)
			}
		}
	}
	// Blocking chains: a waiting session and the one blocking it.
	if blk, err := queryMaps(ctx, db, `SELECT r.session_id AS waiting_pid, r.blocking_session_id AS blocking_pid,
		COALESCE(DB_NAME(r.database_id),'') AS db, r.wait_type AS wait, r.wait_time AS wait_age_secs
		FROM sys.dm_exec_requests r WHERE r.blocking_session_id <> 0`); err == nil {
		MSSQLBlocking(out, blk, now)
	}
	return nil
}

// MSSQLBlocking emits one gauge per blocked session.
func MSSQLBlocking(out sink.Sink, rows []map[string]string, now time.Time) {
	for _, r := range rows {
		a := map[string]string{"db.system.name": "mssql", "waiting_session": r["waiting_pid"],
			"blocking_session": r["blocking_pid"], "db.namespace": r["db"], "wait_type": r["wait"]}
		age, _ := parseF(r["wait_age_secs"])
		out.Gauge("mssql.blocking.wait", "ms", age, a, now)
	}
}

// CollectMSSQLPlans explains the top query-store / cached plans (showplan XML is captured, never
// executed), literals removed (ScrubShowplan).
func CollectMSSQLPlans(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := queryMaps(ctx, db, `SELECT TOP 10 CONVERT(varchar(34), qs.query_hash, 1) AS qhash,
		SUBSTRING(st.text, 1, 200) AS q, CAST(qp.query_plan AS nvarchar(max)) AS plan
		FROM sys.dm_exec_query_stats qs
		CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
		CROSS APPLY sys.dm_exec_query_plan(qs.plan_handle) qp
		WHERE qp.query_plan IS NOT NULL ORDER BY qs.total_worker_time DESC`)
	if err != nil {
		return nil
	}
	for _, r := range rows {
		if !explainable(r["q"]) {
			continue
		}
		EmitPlan(out, "mssql", r["qhash"], r["q"], ScrubShowplan(r["plan"]), now)
	}
	return nil
}

// CollectMSSQLSchema logs the columns of every user table (at most 500).
func CollectMSSQLSchema(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := queryMaps(ctx, db, `SELECT CONCAT(s.name, '.', t.name) AS t,
		CONCAT(c.name, ' ', ty.name, CASE WHEN c.is_nullable = 0 THEN ' not null' ELSE '' END) AS c
		FROM sys.columns c JOIN sys.tables t ON t.object_id = c.object_id
		JOIN sys.schemas s ON s.schema_id = t.schema_id
		JOIN sys.types ty ON ty.user_type_id = c.user_type_id
		ORDER BY s.name, t.name, c.column_id`)
	if err != nil {
		return err
	}
	tables := map[string][]string{}
	var order []string
	for _, r := range rows {
		if _, ok := tables[r["t"]]; !ok {
			if len(order) >= 500 {
				continue
			}
			order = append(order, r["t"])
		}
		tables[r["t"]] = append(tables[r["t"]], r["c"])
	}
	EmitSchema(out, "mssql", order, tables, now)
	return nil
}
