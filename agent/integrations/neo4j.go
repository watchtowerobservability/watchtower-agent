package integrations

// Neo4j (track A2) over the HTTP transactional API, read-only admin commands on the system
// database: database status per member, running transactions (count, slow, lock-waiting), a
// bind-safe sample per slow transaction and blocking chains from "Blocked by" statuses.
// Server metrics (page cache, store sizes) come from Neo4j's Prometheus endpoint via the
// prometheus module where the edition exposes it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Neo4jConfig is the neo4j module's config: the HTTP endpoint (http://host:7474) and a user with
// the SHOW TRANSACTION and SHOW DATABASE privileges.
type Neo4jConfig struct {
	HTTPConfig
	SlowMs int `json:"slow_ms"` // transactions running longer are sampled (default 1000)
}

func (c *Neo4jConfig) check() error { return c.HTTPConfig.check() }

const (
	neo4jTxQuery = `SHOW TRANSACTIONS YIELD database, transactionId, currentQuery, elapsedTime, status, activeLockCount
 RETURN database, transactionId, currentQuery, elapsedTime.milliseconds AS ms, status, activeLockCount`
	neo4jDBQuery = `SHOW DATABASES YIELD name, currentStatus, role RETURN name, currentStatus, role`
)

type neo4jResult struct {
	Results []struct {
		Columns []string `json:"columns"`
		Data    []struct {
			Row []any `json:"row"`
		} `json:"data"`
	} `json:"results"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// rows returns statement i's rows as column -> value maps.
func (r neo4jResult) rows(i int) []map[string]any {
	if i >= len(r.Results) {
		return nil
	}
	res := r.Results[i]
	out := make([]map[string]any, 0, len(res.Data))
	for _, d := range res.Data {
		m := map[string]any{}
		for j, c := range res.Columns {
			if j < len(d.Row) {
				m[c] = d.Row[j]
			}
		}
		out = append(out, m)
	}
	return out
}

// Neo4j polls transactions and databases every 30 s.
func Neo4j(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &Neo4jConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.SlowMs <= 0 {
		c.SlowMs = 1000
	}
	body, _ := json.Marshal(map[string]any{"statements": []map[string]string{{"statement": neo4jTxQuery}, {"statement": neo4jDBQuery}}})
	hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
	return Loop(ctx, "neo4j", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		var r neo4jResult
		if err := doJSON(ctx, c.HTTPConfig, http.MethodPost, c.URL+"/db/system/tx/commit", hdr, body, &r); err != nil {
			return err
		}
		if len(r.Errors) > 0 && len(r.Results) == 0 {
			return errors.New("neo4j: " + sink.Truncate(r.Errors[0].Code, 120))
		}
		EmitNeo4j(out, r, c.SlowMs, now)
		return nil
	})
}

var (
	cypherDoubleQuoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	neo4jBlockedBy     = regexp.MustCompile(`[A-Za-z0-9_.-]+-transaction-\d+`)
)

// CypherSafe removes the literals of a Cypher statement: double-quoted strings here, single-quoted
// strings and numbers through dbm.BindSafe ($parameters are already placeholders).
func CypherSafe(q string) string {
	return dbm.BindSafe(cypherDoubleQuoted.ReplaceAllString(q, "?"))
}

// EmitNeo4j turns the SHOW TRANSACTIONS and SHOW DATABASES rows into series, samples and chains.
func EmitNeo4j(out sink.Sink, r neo4jResult, slowMs int, now time.Time) {
	active := map[string]float64{}
	slow, waiting := 0.0, 0.0
	ids := map[string]int{}
	pid := func(s string) int {
		if _, ok := ids[s]; !ok {
			ids[s] = len(ids) + 1
		}
		return ids[s]
	}
	var sessions []dbm.Session
	for _, t := range r.rows(0) {
		db, _ := t["database"].(string)
		q, _ := t["currentQuery"].(string)
		status, _ := t["status"].(string)
		id, _ := t["transactionId"].(string)
		ms, _ := t["ms"].(float64)
		active[db]++
		text := CypherSafe(q)
		s := dbm.Session{PID: pid(id), State: status, Query: text, AgeMs: ms}
		if strings.HasPrefix(status, "Blocked") {
			waiting++
			for _, b := range neo4jBlockedBy.FindAllString(status, -1) {
				s.BlockedBy = append(s.BlockedBy, pid(b))
			}
		}
		sessions = append(sessions, s)
		if ms >= float64(slowMs) && text != "" && !strings.HasPrefix(strings.ToUpper(text), "SHOW TRANSACTIONS") {
			slow++
			if slow <= 20 {
				locks, _ := t["activeLockCount"].(float64)
				dbm.EmitSample(out, "neo4j", "query.sample", "WARN", map[string]any{"query": text, "running_ms": ms,
					"status": strings.Fields(status + " ")[0], "locks": locks, "state": "running"},
					map[string]string{"db.namespace": db, "db.query.hash": dbm.Hash(text)}, now)
			}
		}
	}
	for db, n := range active {
		out.Gauge("neo4j.transactions.active", "{transactions}", n, map[string]string{"db.namespace": db}, now)
	}
	out.Gauge("neo4j.transactions.slow", "{transactions}", slow, nil, now)
	out.Gauge("neo4j.transactions.blocked", "{transactions}", waiting, nil, now)
	dbm.Report(out, "neo4j", sessions, now)
	for _, d := range r.rows(1) {
		name, _ := d["name"].(string)
		st, _ := d["currentStatus"].(string)
		role, _ := d["role"].(string)
		online := 0.0
		if st == "online" {
			online = 1
		}
		out.Gauge("neo4j.database.online", "1", online, map[string]string{"db.namespace": name, "role": role, "status": st}, now)
	}
}
