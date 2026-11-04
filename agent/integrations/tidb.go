package integrations

// TiDB (track A1) over the MySQL protocol, no exporter: every round TiKV stores (state, regions,
// leaders, capacity), lock waits as blocking chains and new deadlocks from
// information_schema.cluster_deadlocks as `db.deadlock` records (statements bind-safe, keys and
// row handles dropped). `dbm: true` adds per-digest series from
// information_schema.cluster_statements_summary (the current window of every TiDB instance; the
// window reset each tidb_stmt_summary_refresh_interval is a counter reset to the deltas), and
// with `explain` the 5 busiest digests' sample statements are planned every 10 rounds with
// EXPLAIN FORMAT='tidb_json' (TiDB 6.5+; nothing runs), literals removed.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// TiDBConfig is the tidb module's config. DSN (user:pass@tcp(host:4000)/) is local-file only.
type TiDBConfig struct {
	Base
	DSN     string `json:"dsn"`
	DBM     bool   `json:"dbm"`
	Explain bool   `json:"explain"`
}

func (c *TiDBConfig) check() error {
	if c.DSN == "" {
		return errors.New("tidb: dsn is required (in the agent's own config file)")
	}
	return nil
}

type tidbState struct {
	deltas    dbm.Deltas
	deadlocks map[string]bool // instance/deadlock_id already reported
}

// TiDB collects one TiDB cluster.
func TiDB(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &TiDBConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	db, err := sql.Open("mysql", c.DSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	st := &tidbState{}
	round := 0
	return Loop(ctx, "tidb", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		round++
		if c.DBM {
			if rows, err := queryMaps(ctx, db, `SELECT COALESCE(SCHEMA_NAME, '') AS db, DIGEST AS digest,
				MAX(LEFT(DIGEST_TEXT, 1000)) AS q, MAX(QUERY_SAMPLE_TEXT) AS sample, SUM(EXEC_COUNT) AS calls,
				SUM(SUM_LATENCY) / 1000000 AS total_ms, SUM(AVG_RESULT_ROWS * EXEC_COUNT) AS rows_n,
				SUM(AVG_PROCESSED_KEYS * EXEC_COUNT) AS keys_processed, SUM(AVG_TOTAL_KEYS * EXEC_COUNT) AS keys_total
				FROM information_schema.cluster_statements_summary WHERE DIGEST <> ''
				GROUP BY SCHEMA_NAME, DIGEST`); err == nil {
				top := EmitTiDBStatements(out, &st.deltas, rows, now)
				if c.Explain && round%explainEvery == 1 {
					tidbPlans(ctx, db, rows, top, out, now)
				}
			}
		}
		return CollectTiDB(ctx, db, st, out, now)
	})
}

// CollectTiDB reads stores, lock waits and deadlocks.
func CollectTiDB(ctx context.Context, db *sql.DB, st *tidbState, out sink.Sink, now time.Time) error {
	stores, err := queryMaps(ctx, db, `SELECT STORE_ID AS id, ADDRESS AS addr, STORE_STATE_NAME AS state,
		CAPACITY AS cap, AVAILABLE AS avail, LEADER_COUNT AS leaders, REGION_COUNT AS regions
		FROM information_schema.tikv_store_status`)
	if err != nil {
		return err
	}
	EmitTiDBStores(out, stores, now)
	if r, err := queryMaps(ctx, db, `SELECT TRX_ID AS waiting_pid, CURRENT_HOLDING_TRX_ID AS blocking_pid,
		COALESCE(SQL_DIGEST_TEXT, '') AS wq, '' AS bq, 0 AS wait_age_secs FROM information_schema.data_lock_waits LIMIT 200`); err == nil {
		reportBlocking(out, "tidb", r, 1000, now)
	}
	if r, err := queryMaps(ctx, db, `SELECT INSTANCE AS inst, DEADLOCK_ID AS id, OCCUR_TIME AS at,
		TRY_LOCK_TRX_ID AS trx, COALESCE(CURRENT_SQL_DIGEST_TEXT, '') AS q, COALESCE(KEY_INFO, '') AS key_info,
		TRX_HOLDING_LOCK AS holder FROM information_schema.cluster_deadlocks ORDER BY OCCUR_TIME LIMIT 500`); err == nil {
		if st.deadlocks == nil {
			st.deadlocks = map[string]bool{}
		}
		EmitTiDBDeadlocks(out, r, st.deadlocks, now)
	}
	return nil
}

// EmitTiDBStores reports each TiKV/TiFlash store.
func EmitTiDBStores(out sink.Sink, rows []map[string]string, now time.Time) {
	for _, r := range rows {
		a := map[string]string{"store_id": r["id"], "address": r["addr"], "state": r["state"]}
		up := 0.0
		if r["state"] == "Up" {
			up = 1
		}
		out.Gauge("tidb.store.up", "1", up, a, now)
		out.Gauge("tidb.store.regions", "{regions}", sqlNum(r["regions"]), a, now)
		out.Gauge("tidb.store.leaders", "{regions}", sqlNum(r["leaders"]), a, now)
		if c := tidbBytes(r["cap"]); c > 0 {
			out.Gauge("tidb.store.capacity.utilization", "1", 1-tidbBytes(r["avail"])/c, a, now)
		}
	}
}

// tidbBytes reads a store size as TiDB prints it ("1.5TiB", "512GiB", "0B").
func tidbBytes(s string) float64 {
	for i, u := range []string{"EiB", "PiB", "TiB", "GiB", "MiB", "KiB"} {
		if v, ok := strings.CutSuffix(s, u); ok {
			f := sqlNum(v)
			for range 6 - i {
				f *= 1024
			}
			return f
		}
	}
	v, _ := strings.CutSuffix(s, "B")
	return sqlNum(v)
}

// EmitTiDBStatements turns one read of the statement summary into per-digest series. Statement's
// block counters carry processed keys and total keys (total much higher than processed means
// MVCC versions or tombstones are being scanned).
func EmitTiDBStatements(out sink.Sink, d *dbm.Deltas, rows []map[string]string, now time.Time) []dbm.StatementDelta {
	st := make([]dbm.Statement, 0, len(rows))
	for _, r := range rows {
		s := dbm.Statement{Database: r["db"], QueryID: r["digest"], Query: r["q"], Calls: int64(sqlNum(r["calls"])),
			TotalMs: sqlNum(r["total_ms"]), Rows: int64(sqlNum(r["rows_n"])), BlksHit: int64(sqlNum(r["keys_processed"])),
			BlksRead: int64(sqlNum(r["keys_total"]))}
		s.Key = s.Database + "/" + s.QueryID
		st = append(st, s)
	}
	top := d.Observe(st, dbm.MaxStatements)
	for _, s := range top {
		a := map[string]string{"database": s.Database, "digest": s.QueryID, "query": dbm.BindSafe(s.Query)}
		out.Sum("tidb.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("tidb.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("tidb.query.rows", "{rows}", float64(s.Rows), a, now)
		out.Sum("tidb.query.processed_keys", "{keys}", float64(s.BlksHit), a, now)
		out.Sum("tidb.query.total_keys", "{keys}", float64(s.BlksRead), a, now)
		out.Gauge("tidb.query.mean_time", "ms", s.MeanMs, a, now)
	}
	return top
}

func tidbPlans(ctx context.Context, db *sql.DB, rows []map[string]string, top []dbm.StatementDelta, out sink.Sink, now time.Time) {
	sample := map[string]string{}
	for _, r := range rows {
		sample[r["db"]+"/"+r["digest"]] = r["sample"]
	}
	for i, s := range top {
		if i >= 5 {
			return
		}
		q := sample[s.Key]
		if !explainable(q) {
			continue
		}
		if plan, err := explainMySQLAs(ctx, db, s.Database, "EXPLAIN FORMAT='tidb_json' ", q, false); err == nil {
			EmitPlan(out, "tidb", s.QueryID, s.Query, plan, now)
		}
	}
}

// EmitTiDBDeadlocks reports each deadlock not seen before as one db.deadlock record. KEY and the
// handle values of KEY_INFO are row data and are dropped; the table and index names are kept.
func EmitTiDBDeadlocks(out sink.Sink, rows []map[string]string, seen map[string]bool, now time.Time) {
	type txn struct {
		Trx    string `json:"trx"`
		Query  string `json:"query"`
		Table  string `json:"table,omitempty"`
		Index  string `json:"index,omitempty"`
		Holder string `json:"waits_for_trx"`
	}
	var order []string
	byID := map[string][]txn{}
	at := map[string]string{}
	for _, r := range rows {
		id := r["inst"] + "/" + r["id"]
		if seen[id] {
			continue
		}
		var ki struct {
			Table string `json:"table_name"`
			Index string `json:"index_name"`
		}
		_ = json.Unmarshal([]byte(r["key_info"]), &ki)
		if _, ok := byID[id]; !ok {
			order = append(order, id)
		}
		byID[id] = append(byID[id], txn{Trx: r["trx"], Query: dbm.BindSafe(r["q"]), Table: ki.Table, Index: ki.Index, Holder: r["holder"]})
		at[id] = r["at"]
	}
	for _, id := range order {
		if len(seen) >= 10_000 {
			clear(seen)
		}
		seen[id] = true
		body, _ := json.Marshal(map[string]any{"at": at[id], "transactions": byID[id]})
		out.Log("WARN", string(body), map[string]string{"event.name": "db.deadlock", "db.system.name": "tidb",
			"db.deadlock.at": at[id]}, now)
	}
}
