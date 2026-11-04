package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MPL-2.0

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MySQLConfig is the mysql module's config. DSN (user:pass@tcp(host:3306)/) is local-file only.
type MySQLConfig struct {
	Base
	DSN     string `json:"dsn"`
	Schema  bool   `json:"schema"`  // table/column snapshot every 120 rounds (as postgres)
	Explain bool   `json:"explain"` // EXPLAIN FORMAT=JSON of slow recent statements (mysql_explain.go)
	// Database Monitoring (mysql_dbm.go): per-digest deltas and deadlock history, 1 s samples.
	DBM            bool `json:"dbm"`
	CollectSamples bool `json:"collect_samples"`
}

func (c *MySQLConfig) check() error {
	if c.DSN == "" {
		return errors.New("mysql: dsn is required (in the agent's own config file)")
	}
	return nil
}

// mysqlCounters are the SHOW GLOBAL STATUS counters worth a series (cumulative).
var mysqlCounters = map[string]string{
	"Questions": "mysql.questions", "Slow_queries": "mysql.slow_queries", "Connections": "mysql.connections",
	"Aborted_connects": "mysql.aborted_connects", "Aborted_clients": "mysql.aborted_clients",
	"Bytes_received": "mysql.bytes_received", "Bytes_sent": "mysql.bytes_sent",
	"Innodb_row_lock_waits": "mysql.innodb.row_lock_waits", "Created_tmp_disk_tables": "mysql.tmp_disk_tables",
	"Com_select": "mysql.commands.select", "Com_insert": "mysql.commands.insert",
	"Com_update": "mysql.commands.update", "Com_delete": "mysql.commands.delete",
	"Innodb_buffer_pool_read_requests": "mysql.innodb.buffer_pool.read_requests",
	"Innodb_buffer_pool_reads":         "mysql.innodb.buffer_pool.reads",
	"Innodb_buffer_pool_wait_free":     "mysql.innodb.buffer_pool.wait_free",
	"Innodb_buffer_pool_pages_flushed": "mysql.innodb.buffer_pool.pages_flushed",
	"Innodb_row_lock_time":             "mysql.innodb.row_lock_time",
}

var mysqlGauges = map[string]string{
	"Threads_connected": "mysql.threads.connected", "Threads_running": "mysql.threads.running",
	"Max_used_connections": "mysql.max_used_connections", "Innodb_buffer_pool_pages_dirty": "mysql.innodb.dirty_pages",
	"Open_tables":                    "mysql.open_tables",
	"Innodb_buffer_pool_pages_total": "mysql.innodb.buffer_pool.pages_total",
	"Innodb_buffer_pool_pages_free":  "mysql.innodb.buffer_pool.pages_free",
	"Innodb_buffer_pool_pages_data":  "mysql.innodb.buffer_pool.pages_data",
	"Innodb_buffer_pool_bytes_data":  "mysql.innodb.buffer_pool.bytes_data",
	"Innodb_buffer_pool_bytes_dirty": "mysql.innodb.buffer_pool.bytes_dirty",
	"Innodb_row_lock_current_waits":  "mysql.innodb.row_lock_current_waits",
}

// mysqlInnoDBMetrics are information_schema.INNODB_METRICS rows (MySQL 5.6+, MariaDB): name ->
// series, and whether it is a counter.
var mysqlInnoDBMetrics = map[string]struct {
	name    string
	counter bool
}{
	"lock_deadlocks":       {"mysql.innodb.deadlocks", true},
	"lock_timeouts":        {"mysql.innodb.lock_timeouts", true},
	"trx_rseg_history_len": {"mysql.innodb.history_list_length", false},
}

// MySQL collects global status, replica lag and the top 50 statement digests.
func MySQL(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &MySQLConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	db, err := sql.Open("mysql", c.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if c.CollectSamples && (c.Enabled == nil || *c.Enabled) {
		go runMySQLSamples(ctx, c, out)
	}
	var st mysqlDBMState
	round := 0
	return Loop(ctx, "mysql", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		round++
		if c.DBM {
			collectMySQLDBM(ctx, db, &st, out, now)
		}
		if c.Schema && round%schemaEvery == 1 {
			_ = CollectMySQLSchema(ctx, db, out, now)
		}
		if c.Explain && round%explainEvery == 1 {
			_ = CollectMySQLPlans(ctx, db, out, now)
		}
		return CollectMySQL(ctx, db, out, now)
	})
}

// CollectMySQL runs one round.
func CollectMySQL(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	rows, err := queryMaps(ctx, db, "SHOW GLOBAL STATUS")
	if err != nil {
		return err
	}
	for _, r := range rows {
		k, v := r["Variable_name"], r["Value"]
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		if n, ok := mysqlCounters[k]; ok {
			out.Sum(n, "1", f, nil, now)
		} else if n, ok := mysqlGauges[k]; ok {
			out.Gauge(n, "1", f, nil, now)
		}
	}
	// MySQL 8.0.22 renamed SHOW SLAVE STATUS; an empty result is a primary.
	rep, err := queryMaps(ctx, db, "SHOW REPLICA STATUS")
	if err != nil {
		rep, _ = queryMaps(ctx, db, "SHOW SLAVE STATUS")
	}
	for _, r := range rep {
		EmitMySQLReplica(out, r, now)
	}
	if im, err := queryMaps(ctx, db, `SELECT NAME AS n, COUNT AS v FROM information_schema.INNODB_METRICS
		WHERE NAME IN ('lock_deadlocks', 'lock_timeouts', 'trx_rseg_history_len')`); err == nil {
		for _, r := range im {
			m, ok := mysqlInnoDBMetrics[r["n"]]
			f, err := strconv.ParseFloat(r["v"], 64)
			if !ok || err != nil {
				continue
			}
			if m.counter {
				out.Sum(m.name, "1", f, nil, now)
			} else {
				out.Gauge(m.name, "1", f, nil, now)
			}
		}
	}
	// InnoDB lock waits (sys schema, MySQL 5.7+); absent or not granted is skipped.
	if lw, err := queryMaps(ctx, db, `SELECT waiting_pid, blocking_pid, COALESCE(waiting_query,'') AS wq,
		COALESCE(blocking_query,'') AS bq, wait_age_secs FROM sys.innodb_lock_waits LIMIT 200`); err == nil {
		MySQLBlocking(out, lw, now)
	}
	dig, err := queryMaps(ctx, db, `SELECT COALESCE(DIGEST,'') AS digest, LEFT(COALESCE(DIGEST_TEXT,''), 120) AS q, COUNT_STAR AS calls,
		ROUND(SUM_TIMER_WAIT/1000000000, 3) AS total_ms FROM performance_schema.events_statements_summary_by_digest
		ORDER BY SUM_TIMER_WAIT DESC LIMIT 50`)
	if err != nil {
		return nil // performance_schema off or not granted: the rest still counts
	}
	for _, r := range dig {
		a := map[string]string{"digest": r["digest"], "query": r["q"]}
		calls, _ := strconv.ParseFloat(r["calls"], 64)
		ms, _ := strconv.ParseFloat(r["total_ms"], 64)
		out.Sum("mysql.statement.calls", "{calls}", calls, a, now)
		out.Sum("mysql.statement.total_time", "ms", ms, a, now)
	}
	return nil
}

// MySQLBlocking turns sys.innodb_lock_waits rows into blocking chains.
func MySQLBlocking(out sink.Sink, rows []map[string]string, now time.Time) {
	reportBlocking(out, "mysql", rows, 1000, now)
}

// reportBlocking turns waiter/blocker rows (waiting_pid, blocking_pid, wq, bq, wait_age_secs
// times ageToMs) into blocking chains.
func reportBlocking(out sink.Sink, engine string, rows []map[string]string, ageToMs float64, now time.Time) {
	by := map[int]*dbm.Session{}
	get := func(pid int, q string) *dbm.Session {
		s := by[pid]
		if s == nil {
			s = &dbm.Session{PID: pid, Query: q}
			by[pid] = s
		}
		return s
	}
	for _, r := range rows {
		w, _ := strconv.Atoi(r["waiting_pid"])
		b, _ := strconv.Atoi(r["blocking_pid"])
		age, _ := strconv.ParseFloat(r["wait_age_secs"], 64)
		ws := get(w, r["wq"])
		ws.BlockedBy = append(ws.BlockedBy, b)
		ws.AgeMs = age * ageToMs
		get(b, r["bq"])
	}
	all := make([]dbm.Session, 0, len(by))
	for _, s := range by {
		all = append(all, *s)
	}
	dbm.Report(out, engine, all, now)
}

// EmitMySQLReplica reads one SHOW REPLICA|SLAVE STATUS row (either naming).
func EmitMySQLReplica(out sink.Sink, r map[string]string, now time.Time) {
	pick := func(a, b string) string {
		if v, ok := r[a]; ok {
			return v
		}
		return r[b]
	}
	running := func(v string) float64 {
		if strings.EqualFold(v, "Yes") {
			return 1
		}
		return 0
	}
	var a map[string]string // one row per replication channel (multi-source)
	if ch := r["Channel_Name"]; ch != "" {
		a = map[string]string{"channel": ch}
	}
	out.Gauge("mysql.replica.io_running", "1", running(pick("Replica_IO_Running", "Slave_IO_Running")), a, now)
	out.Gauge("mysql.replica.sql_running", "1", running(pick("Replica_SQL_Running", "Slave_SQL_Running")), a, now)
	// NULL lag (replication broken) is reported by the running flags; no point is emitted.
	if lag, err := strconv.ParseFloat(pick("Seconds_Behind_Source", "Seconds_Behind_Master"), 64); err == nil {
		out.Gauge("mysql.replica.lag", "s", lag, a, now)
	}
	// Transactions received but not yet applied: MySQL GTID sets, else MariaDB domain positions.
	behind := int64(-1)
	if rs, es := r["Retrieved_Gtid_Set"], r["Executed_Gtid_Set"]; rs != "" {
		behind = gtidBehind(rs, es)
	} else if io, sp := r["Gtid_IO_Pos"], r["Gtid_Slave_Pos"]; io != "" && sp != "" {
		behind = mariaGTIDBehind(io, sp)
	}
	if behind >= 0 {
		out.Gauge("mysql.replica.gtid_behind", "{transactions}", float64(behind), a, now)
	}
}

// queryMaps returns every row as column name -> text (NULL is "").
func queryMaps(ctx context.Context, db *sql.DB, q string, args ...any) ([]map[string]string, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]string, len(cols))
		for i, c := range cols {
			m[c] = vals[i].String
		}
		out = append(out, m)
		if len(out) >= 5000 {
			break
		}
	}
	return out, rows.Err()
}

// CollectMySQLSchema logs the columns of every user table (at most 500 tables).
func CollectMySQLSchema(ctx context.Context, db *sql.DB, out sink.Sink, now time.Time) error {
	rows, err := queryMaps(ctx, db, `SELECT CONCAT(table_schema, '.', table_name) AS t,
		CONCAT(column_name, ' ', column_type, IF(is_nullable = 'NO', ' not null', '')) AS c
		FROM information_schema.columns WHERE table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		ORDER BY table_schema, table_name, ordinal_position`)
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
	EmitSchema(out, "mysql", order, tables, now)
	return nil
}
