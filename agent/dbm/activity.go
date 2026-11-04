package dbm

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MaxSampleGroups bounds the sample records reported per flush.
const MaxSampleGroups = 100

// Activity is one non-idle session in one snapshot of the engine's activity view.
type Activity struct {
	Database   string
	State      string
	WaitType   string // wait_event_type ("" when on CPU)
	Wait       string // wait_event
	QueryID    string
	Query      string // raw text: kept in memory for EXPLAIN only, never reported as is
	DurationMs float64
}

type sampleKey struct{ db, state, waitType, wait, query string }

type sampleGroup struct {
	queryID string
	raw     string
	samples int
	maxMs   float64
}

// Sampler aggregates activity snapshots (taken every second) into groups of database, state,
// wait event and statement, so the agent ships one record per group per flush instead of one
// per session per second. Not safe for concurrent use.
type Sampler struct {
	ticks  int
	groups map[sampleKey]*sampleGroup
}

// Add records one snapshot.
func (s *Sampler) Add(rows []Activity) {
	if s.groups == nil {
		s.groups = map[sampleKey]*sampleGroup{}
	}
	s.ticks++
	for _, r := range rows {
		k := sampleKey{r.Database, r.State, r.WaitType, r.Wait, BindSafe(r.Query)}
		g := s.groups[k]
		if g == nil {
			if len(s.groups) >= 10*MaxSampleGroups {
				continue
			}
			g = &sampleGroup{queryID: r.QueryID}
			s.groups[k] = g
		}
		g.samples++
		g.raw = r.Query
		g.maxMs = max(g.maxMs, r.DurationMs)
	}
}

// Ticks is the number of snapshots since the last flush.
func (s *Sampler) Ticks() int { return s.ticks }

// Candidate is a sampled statement the caller may EXPLAIN: Raw is the text as the engine ran it
// (with literals), Query its bind-safe form.
type Candidate struct{ QueryID, Query, Raw string }

// Flush emits what was sampled since the last flush and resets: `db.activity.sessions` (average
// sessions per database, state and wait event: active session history) and one
// `db.query.sample` log record per group, busiest first. It returns one candidate per statement.
func (s *Sampler) Flush(out sink.Sink, engine string, now time.Time) []Candidate {
	if s.ticks == 0 {
		return nil
	}
	type waitKey struct{ db, state, waitType, wait string }
	load := map[waitKey]int{}
	keys := make([]sampleKey, 0, len(s.groups))
	for k, g := range s.groups {
		load[waitKey{k.db, k.state, k.waitType, k.wait}] += g.samples
		keys = append(keys, k)
	}
	for k, n := range load {
		out.Gauge("db.activity.sessions", "{sessions}", float64(n)/float64(s.ticks), map[string]string{
			"db.system.name": engine, "db.namespace": k.db, "db.session.state": k.state,
			"db.wait_event_type": orCPU(k.waitType), "db.wait_event": orCPU(k.wait),
		}, now)
	}
	sort.Slice(keys, func(i, j int) bool { return s.groups[keys[i]].samples > s.groups[keys[j]].samples })
	var cands []Candidate
	seen := map[string]bool{}
	for i, k := range keys {
		if i >= MaxSampleGroups {
			break
		}
		g := s.groups[k]
		body, _ := json.Marshal(map[string]any{"query": k.query, "samples": g.samples, "ticks": s.ticks,
			"max_duration_ms": g.maxMs, "wait_event_type": k.waitType, "wait_event": k.wait, "state": k.state})
		out.Log("INFO", string(body), map[string]string{
			"event.name": "db.query.sample", "db.system.name": engine, "db.namespace": k.db,
			"db.query.id": g.queryID, "db.query.text": k.query, "db.session.state": k.state,
			"db.wait_event_type": orCPU(k.waitType), "db.wait_event": orCPU(k.wait),
			"db.sample.count": strconv.Itoa(g.samples),
		}, now)
		if k.query != "" && !seen[k.query] {
			seen[k.query] = true
			cands = append(cands, Candidate{QueryID: g.queryID, Query: k.query, Raw: g.raw})
		}
	}
	s.ticks, s.groups = 0, nil
	return cands
}

func orCPU(s string) string {
	if s == "" {
		return "CPU"
	}
	return s
}
