package integrations

// Slow-query log tailing (track A1): the `db_slow_log` module follows a MySQL/MariaDB slow query
// log or a PostgreSQL server log (log_min_duration_statement and auto_explain output) and ships
// each slow statement as a `db.query.sample` record (db.sample.source slow_log, auto_explain or
// duration_log) with its text made bind-safe, so the raw log, which carries literals, never leaves
// the host. auto_explain plans in JSON format (auto_explain.log_format = json) also become
// `db.query.plan` records with every literal removed; text-format plans are not shipped.
// shortcut: offsets live in memory (a restart resumes at the end of the file); upgrade by
// handing modules the agent's state dir.

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/logs"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// SlowLogConfig is the db_slow_log module's local config.
type SlowLogConfig struct {
	Base
	Engine string `json:"engine"` // mysql (MariaDB too) or postgresql
	Path   string `json:"path"`   // file or glob
}

func (c *SlowLogConfig) check() error {
	if c.Engine != "mysql" && c.Engine != "postgresql" {
		return errors.New("db_slow_log: engine must be mysql or postgresql")
	}
	if c.Path == "" {
		return errors.New("db_slow_log: path is required")
	}
	return nil
}

// DBSlowLog follows the log until ctx ends.
func DBSlowLog(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &SlowLogConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	// A MySQL record starts at "# Time:"; a PostgreSQL one at any line not indented.
	start := `^# Time: `
	if c.Engine == "postgresql" {
		start = `^\S`
	}
	t, err := logs.NewTailer([]logs.TailSpec{{Path: c.Path, MultilineStart: start}}, logs.MemState(),
		slowLogSink{out: out, engine: c.Engine})
	if err != nil {
		return err
	}
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		t.Poll(time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
		}
	}
}

// slowLogSink turns tailed records into samples; everything else is dropped.
type slowLogSink struct {
	out    sink.Sink
	engine string
}

func (s slowLogSink) Gauge(string, string, float64, map[string]string, time.Time) {}
func (s slowLogSink) Sum(string, string, float64, map[string]string, time.Time)   {}

func (s slowLogSink) Log(_, body string, _ map[string]string, at time.Time) {
	var qs []SlowQuery
	if s.engine == "mysql" {
		qs = ParseMySQLSlow(body)
	} else if q, ok := ParsePGSlow(body); ok {
		qs = []SlowQuery{q}
	}
	for _, q := range qs {
		EmitSlowQuery(s.out, s.engine, q, at)
	}
}

// SlowQuery is one statement from a slow log, already bind-safe.
type SlowQuery struct {
	Source       string  `json:"source"`
	Database     string  `json:"-"`
	Query        string  `json:"query"`
	DurationMs   float64 `json:"duration_ms"`
	LockMs       float64 `json:"lock_ms,omitempty"`
	RowsSent     float64 `json:"rows_sent,omitempty"`
	RowsExamined float64 `json:"rows_examined,omitempty"`
	User         string  `json:"user,omitempty"`
	Plan         string  `json:"-"` // bind-safe JSON plan (auto_explain json)
	Hash         string  `json:"-"` // db.query.hash of the raw statement
}

// EmitSlowQuery writes the sample and, when there is one, the plan.
func EmitSlowQuery(out sink.Sink, engine string, q SlowQuery, at time.Time) {
	body, _ := json.Marshal(q)
	out.Log("INFO", string(body), map[string]string{"event.name": "db.query.sample", "db.system.name": engine,
		"db.namespace": q.Database, "db.query.text": q.Query, "db.query.hash": q.Hash, "db.sample.source": q.Source}, at)
	if q.Plan != "" {
		EmitPlan(out, engine, "", q.Query, q.Plan, at)
	}
}

var reSlowKV = regexp.MustCompile(`(\w+): +(\S+)`)

// ParseMySQLSlow reads one record of a MySQL/MariaDB slow log. Before 5.7 several statements may
// share one "# Time:" line, so a record can hold more than one.
func ParseMySQLSlow(body string) []SlowQuery {
	var out []SlowQuery
	var cur SlowQuery
	kv := map[string]string{}
	var text []string
	flush := func() {
		if _, ok := kv["Query_time"]; ok && len(text) > 0 {
			cur.Source = "slow_log"
			cur.DurationMs = sqlNum(kv["Query_time"]) * 1000
			cur.LockMs = sqlNum(kv["Lock_time"]) * 1000
			cur.RowsSent, cur.RowsExamined = sqlNum(kv["Rows_sent"]), sqlNum(kv["Rows_examined"])
			if s := kv["Schema"]; s != "" && cur.Database == "" { // MariaDB
				cur.Database = s
			}
			raw := strings.Join(text, " ")
			cur.Query, cur.Hash = dbm.BindSafe(raw), dbm.QueryHash(raw, false)
			out = append(out, cur)
		}
		db := cur.Database // a "use" line holds for the statements after it
		cur, kv, text = SlowQuery{Database: db}, map[string]string{}, nil
	}
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimRight(ln, "\r")
		switch {
		case strings.HasPrefix(ln, "# User@Host:"):
			if len(text) > 0 {
				flush()
			}
			u := strings.TrimSpace(strings.TrimPrefix(ln, "# User@Host:"))
			cur.User, _, _ = strings.Cut(u, "[")
		case strings.HasPrefix(ln, "# administrator command"):
			text = nil
		case strings.HasPrefix(ln, "#"):
			for _, m := range reSlowKV.FindAllStringSubmatch(ln, -1) {
				kv[m[1]] = m[2]
			}
		case strings.HasPrefix(strings.ToLower(ln), "use "):
			cur.Database = strings.Trim(strings.TrimSpace(ln[4:]), "`;")
		case strings.HasPrefix(strings.ToUpper(ln), "SET TIMESTAMP="):
		case strings.TrimSpace(ln) != "":
			text = append(text, strings.TrimSpace(ln))
		}
	}
	flush()
	return out
}

var (
	rePGDur = regexp.MustCompile(`duration: ([0-9.]+) ms +(plan|statement|execute [^:]*):`)
	rePGDB  = regexp.MustCompile(`\bdb=([^,\s\]]+)`)
	rePGUsr = regexp.MustCompile(`\buser=([^,\s\]]+)`)
)

// ParsePGSlow reads one PostgreSQL log record: a log_min_duration_statement line ("duration: 12 ms
// statement: ...", or "execute <name>: ...") or an auto_explain one ("duration: 12 ms  plan:"
// followed by the indented plan). The database and user come from db=%d / user=%u in
// log_line_prefix when present.
func ParsePGSlow(body string) (SlowQuery, bool) {
	m := rePGDur.FindStringSubmatchIndex(body)
	if m == nil {
		return SlowQuery{}, false
	}
	head := body[:m[0]]
	q := SlowQuery{DurationMs: sqlNum(body[m[2]:m[3]]), Source: "duration_log"}
	if d := rePGDB.FindStringSubmatch(head); d != nil {
		q.Database = d[1]
	}
	if u := rePGUsr.FindStringSubmatch(head); u != nil {
		q.User = u[1]
	}
	var lines []string
	for _, ln := range strings.Split(body[m[1]:], "\n") {
		lines = append(lines, strings.TrimPrefix(strings.TrimRight(ln, "\r"), "\t"))
	}
	rest := strings.TrimSpace(strings.Join(lines, "\n"))
	if body[m[4]:m[5]] != "plan" {
		q.Query, q.Hash = dbm.BindSafe(rest), dbm.QueryHash(rest, true)
		return q, q.Query != ""
	}
	q.Source = "auto_explain"
	if strings.HasPrefix(rest, "{") {
		var doc struct {
			Text string          `json:"Query Text"`
			Plan json.RawMessage `json:"Plan"`
		}
		if json.Unmarshal([]byte(rest), &doc) != nil {
			return q, false
		}
		q.Query, q.Hash = dbm.BindSafe(doc.Text), dbm.QueryHash(doc.Text, true)
		if len(doc.Plan) > 0 {
			b, _ := json.Marshal([]map[string]json.RawMessage{{"Plan": doc.Plan}})
			q.Plan = dbm.ObfuscatePlan(string(b))
		}
		return q, q.Query != ""
	}
	// Text format: "Query Text: ..." then the plan, which is not shipped (its filters carry
	// literals). shortcut: a multi-line query keeps only its first line.
	first, _, _ := strings.Cut(rest, "\n")
	first = strings.TrimPrefix(first, "Query Text: ")
	q.Query, q.Hash = dbm.BindSafe(first), dbm.QueryHash(first, true)
	return q, q.Query != ""
}
