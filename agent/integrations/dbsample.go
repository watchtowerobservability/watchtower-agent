package integrations

// Shared loop of the agent-side activity samplers (MySQL, SQL Server, Oracle, TiDB, CockroachDB;
// Postgres has its own in postgres_dbm.go): a snapshot every second, aggregated by dbm.Sampler
// and flushed every 10, with an optional EXPLAIN of the sampled statements behind a rate gate.

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	dbSampleEvery     = time.Second
	dbSampleFlush     = 10 // snapshots per flush
	dbExplainPerSig   = 10 * time.Minute
	dbExplainPerRound = 5
)

// sampleLoop runs until ctx ends. snap reads one snapshot (2 s timeout); a failed snapshot is
// logged and retried after 10 s. explain (nil: none) gets the candidates of each flush and the sink that stamps db.query.hash.
func sampleLoop(ctx context.Context, engine string, out sink.Sink,
	snap func(ctx context.Context) ([]dbm.Activity, error),
	explain func(ctx context.Context, out sink.Sink, cands []dbm.Candidate, now time.Time),
) {
	var s dbm.Sampler
	hs := &hashSink{Sink: out, pg: dbm.PGDialect(engine), raw: map[string]string{}}
	t := time.NewTicker(dbSampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		rows, err := snap(sctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("activity sampling failed", "db.system.name", engine, "error", sink.Truncate(err.Error(), 300))
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}
		s.Add(rows)
		for _, a := range rows {
			if len(hs.raw) < 10*dbm.MaxSampleGroups {
				hs.raw[dbm.BindSafe(a.Query)] = a.Query
			}
		}
		if s.Ticks() < dbSampleFlush {
			continue
		}
		now := time.Now()
		cands := s.Flush(hs, engine, now)
		if explain != nil {
			explain(ctx, hs, cands, now)
		}
		clear(hs.raw)
	}
}

// hashSink adds db.query.hash, computed from the raw statement (the canonical normalizer needs
// the text as the engine ran it), to sample records whose bind-safe text it saw this flush.
type hashSink struct {
	sink.Sink
	pg  bool
	raw map[string]string // bind-safe text -> raw text
}

func (h *hashSink) Log(sev, body string, a map[string]string, at time.Time) {
	if q, ok := h.raw[a["db.query.text"]]; ok && q != "" && a["db.query.hash"] == "" {
		a["db.query.hash"] = dbm.QueryHash(q, h.pg)
	}
	h.Sink.Log(sev, body, a, at)
}

// explainGate lets a statement be planned at most once per dbExplainPerSig and at most
// dbExplainPerRound statements per flush. Failures count too: a statement that cannot be
// planned is not retried. Not safe for concurrent use.
type explainGate struct{ done map[string]time.Time }

// pick returns the explainable candidates to plan now.
func (g *explainGate) pick(cands []dbm.Candidate, now time.Time) []dbm.Candidate {
	if g.done == nil {
		g.done = map[string]time.Time{}
	}
	for k, at := range g.done {
		if now.Sub(at) > dbExplainPerSig {
			delete(g.done, k)
		}
	}
	var out []dbm.Candidate
	for _, c := range cands {
		if len(out) >= dbExplainPerRound || len(g.done) >= 10_000 {
			break
		}
		if _, ok := g.done[c.Query]; ok || !explainable(c.Raw) {
			continue
		}
		g.done[c.Query] = now
		out = append(out, c)
	}
	return out
}

// waitSplit turns an engine wait name into (type, event) for db.activity.sessions: the part
// before the first sep is the type ("io/table/sql/handler" -> "io"). "" stays "" (on CPU).
func waitSplit(name, sep string) (string, string) {
	t, _, _ := strings.Cut(name, sep)
	return t, name
}
