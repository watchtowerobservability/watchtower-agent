package integrations

// MySQL / MariaDB Database Monitoring run by the agent (track A1), opt-in, the same model as
// postgres_dbm.go:
//
//   - `dbm: true`: per-digest series from performance_schema.events_statements_summary_by_digest
//     deltas every round: mysql.query.{calls,total_time,rows_sent,rows_examined,no_index_used}
//     (agent-side running totals that survive TRUNCATE of the summary) and mysql.query.mean_time,
//     labelled database, digest and the bind-safe query; plus the InnoDB deadlock history: one
//     `db.deadlock` record per new LATEST DETECTED DEADLOCK of SHOW ENGINE INNODB STATUS (no row
//     data: only statements made bind-safe, tables, indexes and lock modes).
//   - `collect_samples: true`: the running statements with their current wait every second
//     (performance_schema.threads + events_statements_current + events_waits_current; the
//     events_waits_current consumer must be on for waits, else they read as CPU), shipped every
//     10 s as db.activity.sessions and db.query.sample.
//   - with `collect_samples` and `explain`: sampled SELECTs are explained in their schema
//     (mysql_explain.go), at most 5 per 10 s and each once per 10 minutes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// mysqlDBMState is what the round loop keeps between rounds.
type mysqlDBMState struct {
	deltas       dbm.Deltas
	lastDeadlock string
}

func collectMySQLDBM(ctx context.Context, db *sql.DB, st *mysqlDBMState, out sink.Sink, now time.Time) {
	if rows, err := queryMaps(ctx, db, `SELECT COALESCE(SCHEMA_NAME, '') AS db, DIGEST AS digest,
		LEFT(COALESCE(DIGEST_TEXT, ''), 1000) AS q, COUNT_STAR AS calls, SUM_TIMER_WAIT / 1000000000 AS total_ms,
		SUM_ROWS_SENT AS rows_sent, SUM_ROWS_EXAMINED AS rows_examined,
		SUM_NO_INDEX_USED + SUM_NO_GOOD_INDEX_USED AS no_index
		FROM performance_schema.events_statements_summary_by_digest WHERE DIGEST IS NOT NULL
		ORDER BY SUM_TIMER_WAIT DESC LIMIT 5000`); err == nil {
		EmitMySQLDigests(out, &st.deltas, rows, now)
	}
	if rows, err := queryMaps(ctx, db, "SHOW ENGINE INNODB STATUS"); err == nil && len(rows) == 1 {
		if d, ok := ParseInnoDBDeadlock(rows[0]["Status"]); ok && d.At != st.lastDeadlock {
			st.lastDeadlock = d.At
			body, _ := json.Marshal(d)
			out.Log("WARN", string(body), map[string]string{"event.name": "db.deadlock", "db.system.name": "mysql",
				"db.deadlock.at": d.At, "db.deadlock.transactions": strconv.Itoa(len(d.Transactions))}, now)
		}
	}
}

func sqlNum(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// EmitMySQLDigests turns one read of the digest summary into per-digest series. Statement's two
// block counters carry MySQL's rows examined and no-index-used counts.
func EmitMySQLDigests(out sink.Sink, d *dbm.Deltas, rows []map[string]string, now time.Time) {
	st := make([]dbm.Statement, 0, len(rows))
	for _, r := range rows {
		s := dbm.Statement{Database: r["db"], QueryID: r["digest"], Query: r["q"], Calls: int64(sqlNum(r["calls"])),
			TotalMs: sqlNum(r["total_ms"]), Rows: int64(sqlNum(r["rows_sent"])), BlksHit: int64(sqlNum(r["rows_examined"])),
			BlksRead: int64(sqlNum(r["no_index"]))}
		s.Key = s.Database + "/" + s.QueryID
		st = append(st, s)
	}
	for _, s := range d.Observe(st, dbm.MaxStatements) {
		a := map[string]string{"database": s.Database, "digest": s.QueryID, "query": dbm.BindSafe(s.Query)}
		out.Sum("mysql.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("mysql.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("mysql.query.rows_sent", "{rows}", float64(s.Rows), a, now)
		out.Sum("mysql.query.rows_examined", "{rows}", float64(s.BlksHit), a, now)
		out.Sum("mysql.query.no_index_used", "{calls}", float64(s.BlksRead), a, now)
		out.Gauge("mysql.query.mean_time", "ms", s.MeanMs, a, now)
	}
}

const mysqlSampleSQL = `SELECT COALESCE(t.PROCESSLIST_DB, '') AS db, COALESCE(t.PROCESSLIST_COMMAND, '') AS state,
	COALESCE(w.EVENT_NAME, '') AS wait, COALESCE(s.DIGEST, '') AS digest, COALESCE(s.SQL_TEXT, '') AS q,
	COALESCE(s.TIMER_WAIT, 0) / 1000000000 AS ms
	FROM performance_schema.threads t
	JOIN performance_schema.events_statements_current s ON s.THREAD_ID = t.THREAD_ID AND s.END_EVENT_ID IS NULL
	LEFT JOIN performance_schema.events_waits_current w ON w.THREAD_ID = t.THREAD_ID AND w.END_EVENT_ID IS NULL
	WHERE t.TYPE = 'FOREGROUND' AND t.PROCESSLIST_ID <> CONNECTION_ID()
	AND COALESCE(t.PROCESSLIST_COMMAND, '') <> 'Sleep'`

// MySQLActivity maps sampled rows; a wait "wait/io/table/sql/handler" has type "io".
func MySQLActivity(rows []map[string]string) []dbm.Activity {
	out := make([]dbm.Activity, 0, len(rows))
	for _, r := range rows {
		wt, w := waitSplit(strings.TrimPrefix(r["wait"], "wait/"), "/")
		out = append(out, dbm.Activity{Database: r["db"], State: r["state"], WaitType: wt, Wait: w,
			QueryID: r["digest"], Query: r["q"], DurationMs: sqlNum(r["ms"])})
	}
	return out
}

// runMySQLSamples samples on its own connection so a slow round never delays a snapshot.
func runMySQLSamples(ctx context.Context, c *MySQLConfig, out sink.Sink) {
	db, err := sql.Open("mysql", c.DSN)
	if err != nil {
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	schemaOf := map[string]string{} // bind-safe text -> schema it last ran in (for EXPLAIN)
	snap := func(ctx context.Context) ([]dbm.Activity, error) {
		rows, err := queryMaps(ctx, db, mysqlSampleSQL)
		if err != nil {
			return nil, err
		}
		act := MySQLActivity(rows)
		for _, a := range act {
			if len(schemaOf) < 10*dbm.MaxSampleGroups {
				schemaOf[dbm.BindSafe(a.Query)] = a.Database
			}
		}
		return act, nil
	}
	var explain func(context.Context, sink.Sink, []dbm.Candidate, time.Time)
	if c.Explain {
		var gate explainGate
		explain = func(ctx context.Context, out sink.Sink, cands []dbm.Candidate, now time.Time) {
			for _, cd := range gate.pick(cands, now) {
				if plan, err := explainMySQL(ctx, db, schemaOf[cd.Query], cd.Raw); err == nil {
					EmitPlan(out, "mysql", cd.QueryID, cd.Query, plan, now)
				}
			}
			clear(schemaOf)
		}
	}
	sampleLoop(ctx, "mysql", out, snap, explain)
}

// MySQLDeadlock is the LATEST DETECTED DEADLOCK section of SHOW ENGINE INNODB STATUS without its
// row dumps.
type MySQLDeadlock struct {
	At           string             `json:"at"`
	Transactions []MySQLDeadlockTxn `json:"transactions"`
	RolledBack   int                `json:"rolled_back,omitempty"` // 1-based index into Transactions
}

// MySQLDeadlockTxn is one transaction of a deadlock: its statement and the lock it held and the
// one it waited for.
type MySQLDeadlockTxn struct {
	Query    string `json:"query"`
	Table    string `json:"table,omitempty"`
	Index    string `json:"index,omitempty"`
	Holds    string `json:"holds,omitempty"`
	WaitsFor string `json:"waits_for,omitempty"`
}

var (
	reDLTxn  = regexp.MustCompile(`^\*\*\* \((\d+)\) TRANSACTION:`)
	reDLBack = regexp.MustCompile(`^\*\*\* WE ROLL BACK TRANSACTION \((\d+)\)`)
	reDLLock = regexp.MustCompile(`(?:index (\S+) of )?table (\S+)(?: trx id \d+)? lock[_ ]mode (\S+(?: locks (?:rec but not gap|gap before rec))?)`)
)

// ParseInnoDBDeadlock reads the deadlock section; false when there is none.
func ParseInnoDBDeadlock(status string) (MySQLDeadlock, bool) {
	var d MySQLDeadlock
	_, sec, ok := strings.Cut(status, "LATEST DETECTED DEADLOCK\n")
	if !ok {
		return d, false
	}
	lines := strings.Split(sec, "\n")
	var cur *MySQLDeadlockTxn
	mode, inQuery := "", false
	for i, ln := range lines {
		if i == 0 {
			continue // the dashes under the title
		}
		if d.At == "" && strings.TrimSpace(ln) != "" {
			f := strings.Fields(ln)
			d.At = strings.Join(f[:min(2, len(f))], " ")
			continue
		}
		if strings.HasPrefix(ln, "------------") { // the next section
			break
		}
		switch {
		case reDLTxn.MatchString(ln):
			d.Transactions = append(d.Transactions, MySQLDeadlockTxn{})
			cur, mode, inQuery = &d.Transactions[len(d.Transactions)-1], "", false
		case reDLBack.MatchString(ln):
			d.RolledBack, _ = strconv.Atoi(reDLBack.FindStringSubmatch(ln)[1])
		case cur == nil:
		case strings.HasPrefix(ln, "MySQL thread id"):
			inQuery = true
		case strings.HasPrefix(ln, "***"):
			inQuery = false
			if strings.Contains(ln, "HOLDS THE LOCK") {
				mode = "holds"
			} else if strings.Contains(ln, "WAITING FOR THIS LOCK") {
				mode = "waits"
			}
		case inQuery && strings.TrimSpace(ln) == "":
			inQuery = false
		case inQuery:
			cur.Query = dbm.BindSafe(strings.TrimSpace(cur.Query + " " + ln))
		case mode != "" && (strings.HasPrefix(ln, "RECORD LOCKS") || strings.HasPrefix(ln, "TABLE LOCK")):
			m := reDLLock.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			if cur.Table == "" || mode == "waits" {
				cur.Index, cur.Table = m[1], m[2]
			}
			if mode == "holds" {
				cur.Holds = m[3]
			} else {
				cur.WaitsFor = m[3]
			}
		}
	}
	return d, d.At != "" && len(d.Transactions) > 0
}

// gtidBehind counts the transactions of a MySQL GTID set retrieved that executed lacks
// ("uuid:1-5:7,uuid2:tag:1-3"); -1 when retrieved does not parse.
func gtidBehind(retrieved, executed string) int64 {
	r, e := parseGTIDSet(retrieved), parseGTIDSet(executed)
	if r == nil {
		return -1
	}
	var n int64
	for k, ivs := range r {
		for _, iv := range ivs {
			n += iv[1] - iv[0] + 1
			for _, x := range e[k] {
				n -= max(0, min(iv[1], x[1])-max(iv[0], x[0])+1)
			}
		}
	}
	return max(n, 0)
}

func parseGTIDSet(s string) map[string][][2]int64 {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil
	}
	out := map[string][][2]int64{}
	for _, part := range strings.Split(s, ",") {
		f := strings.Split(part, ":")
		key := strings.ToLower(f[0])
		for _, iv := range f[1:] {
			if iv == "" || iv[0] < '0' || iv[0] > '9' {
				key = strings.ToLower(f[0]) + ":" + iv // a tagged GTID (MySQL 8.3+)
				continue
			}
			a, b, rng := strings.Cut(iv, "-")
			lo, err := strconv.ParseInt(a, 10, 64)
			if err != nil {
				return nil
			}
			hi := lo
			if rng {
				if hi, err = strconv.ParseInt(b, 10, 64); err != nil {
					return nil
				}
			}
			out[key] = append(out[key], [2]int64{lo, hi})
		}
	}
	return out
}

// mariaGTIDBehind compares MariaDB positions ("domain-server-seq,..."): per domain, the sequence
// received minus the one applied; -1 when io does not parse.
func mariaGTIDBehind(io, applied string) int64 {
	seqs := func(s string) map[string]int64 {
		m := map[string]int64{}
		for _, g := range strings.Split(strings.Join(strings.Fields(s), ""), ",") {
			f := strings.Split(g, "-")
			if len(f) != 3 {
				return nil
			}
			n, err := strconv.ParseInt(f[2], 10, 64)
			if err != nil {
				return nil
			}
			m[f[0]] = n
		}
		return m
	}
	r, a := seqs(io), seqs(applied)
	if r == nil {
		return -1
	}
	var n int64
	for dom, seq := range r {
		n += max(0, seq-a[dom])
	}
	return n
}
