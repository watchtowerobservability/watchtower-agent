package dbm

import (
	"encoding/json"
	"sort"
)

// MaxStatements bounds the per-query series reported per round.
const MaxStatements = 200

// Statement is one row of the engine's statement statistics (pg_stat_statements), cumulative
// since the engine last reset them.
type Statement struct {
	Key      string // e.g. database + "/" + queryid
	QueryID  string
	Database string
	Query    string
	Calls    int64
	TotalMs  float64
	Rows     int64
	BlksHit  int64
	BlksRead int64
}

// StatementDelta is one statement's activity since the previous round plus the agent's own
// running totals of it, which keep counting across an engine reset or eviction.
type StatementDelta struct {
	Statement           // running totals
	MeanMs    float64   // of the calls in this round
	Delta     Statement // this round only
}

// Deltas turns cumulative statement rows into per-round deltas. Not safe for concurrent use.
type Deltas struct {
	prev map[string]Statement
	acc  map[string]Statement
}

// Observe takes one round of rows and returns the statements that ran since the previous round,
// most total time first, at most limit. A statement seen for the first time sets its baseline
// only (its history is not this round's work). A counter that went down was reset, so its
// current value is the delta.
func (d *Deltas) Observe(rows []Statement, limit int) []StatementDelta {
	if d.prev == nil {
		d.prev, d.acc = map[string]Statement{}, map[string]Statement{}
	}
	cur := make(map[string]Statement, len(rows))
	var out []StatementDelta
	for _, r := range rows {
		cur[r.Key] = r
		p, ok := d.prev[r.Key]
		if !ok {
			continue
		}
		dl := r
		if r.Calls < p.Calls || r.TotalMs < p.TotalMs {
			p = Statement{} // reset since last round
		}
		dl.Calls, dl.TotalMs, dl.Rows = r.Calls-p.Calls, r.TotalMs-p.TotalMs, r.Rows-p.Rows
		dl.BlksHit, dl.BlksRead = r.BlksHit-p.BlksHit, r.BlksRead-p.BlksRead
		if dl.Calls <= 0 {
			continue
		}
		a := d.acc[r.Key]
		a.Key, a.QueryID, a.Database, a.Query = r.Key, r.QueryID, r.Database, r.Query
		a.Calls += dl.Calls
		a.TotalMs += dl.TotalMs
		a.Rows += max(dl.Rows, 0)
		a.BlksHit += max(dl.BlksHit, 0)
		a.BlksRead += max(dl.BlksRead, 0)
		d.acc[r.Key] = a
		out = append(out, StatementDelta{Statement: a, MeanMs: dl.TotalMs / float64(dl.Calls), Delta: dl})
	}
	// Evicted statements drop out; their series restart at 0 if they come back (a counter reset).
	for k := range d.acc {
		if _, ok := cur[k]; !ok {
			delete(d.acc, k)
		}
	}
	d.prev = cur
	sort.Slice(out, func(i, j int) bool { return out[i].Delta.TotalMs > out[j].Delta.TotalMs })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ObfuscatePlan makes an EXPLAIN (FORMAT JSON) document bind-safe: every string value
// (conditions, filters, outputs) goes through BindSafe, so a plan of a statement run with real
// literals never carries them. Keys and numbers (costs, rows) are kept. "" if it is not JSON.
func ObfuscatePlan(plan string) string {
	var v any
	if json.Unmarshal([]byte(plan), &v) != nil {
		return ""
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			return BindSafe(t)
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case map[string]any:
			for k := range t {
				t[k] = walk(t[k])
			}
		}
		return x
	}
	b, err := json.Marshal(walk(v))
	if err != nil {
		return ""
	}
	return string(b)
}
