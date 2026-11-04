package integrations

// Postgres Database Monitoring run by the agent inside the customer network (W36), opt-in:
//
//   - `dbm: true` exports per-queryid series from pg_stat_statements deltas every round:
//     postgresql.query.{calls,total_time,rows,blks_hit,blks_read} (agent-side running totals
//     that survive pg_stat_statements_reset) and postgresql.query.mean_time (this round).
//   - `collect_samples: true` samples pg_stat_activity every second with its wait event and
//     ships `db.activity.sessions` plus `db.query.sample` log records every 10 s.
//   - with both `collect_samples` and `explain`, sampled statements are planned through the
//     optional SECURITY DEFINER function `explain_function` (default
//     watchtower.explain_statement, DDL in docs/product/infra/integrations.md) at most once
//     per statement per 10 minutes, with a 2 s statement timeout; the plan is made bind-safe
//     before it leaves the agent. Without the function, `explain` keeps the GENERIC_PLAN path
//     (postgres_plans.go), and the API's SaaS-side EXPLAIN stays the fallback for databases it
//     can reach.
//
// Everything goes out on the agent's normal OTLP export (metrics and logs), like the blocking
// chains of ../dbm.

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	sampleEvery     = time.Second
	sampleFlush     = 10 // snapshots per flush
	explainPerSig   = 10 * time.Minute
	explainPerRound = 5
	defaultExplain  = "watchtower.explain_statement"
)

var explainFnRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$`)

func (c *PostgresConfig) checkDBM() error {
	if c.ExplainFunction != "" && !explainFnRE.MatchString(c.ExplainFunction) {
		return errors.New("postgres: explain_function must be schema.function (lower case)")
	}
	return nil
}

// CollectStatementDeltas reads pg_stat_statements (PostgreSQL 13+) and emits the per-queryid
// series of the statements that ran since the previous round.
func CollectStatementDeltas(ctx context.Context, dsn string, d *dbm.Deltas, out sink.Sink, now time.Time) error {
	conn, err := pgConn(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var rows []dbm.Statement
	err = each(ctx, conn, `SELECT d.datname, s.queryid::text, sum(s.calls)::int8, sum(s.total_exec_time)::float8,
		sum(s.rows)::int8, sum(s.shared_blks_hit)::int8, sum(s.shared_blks_read)::int8, left(min(s.query), 1000)
		FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid
		WHERE s.queryid IS NOT NULL GROUP BY 1, 2`, func(r pgx.Rows) error {
		var s dbm.Statement
		if err := r.Scan(&s.Database, &s.QueryID, &s.Calls, &s.TotalMs, &s.Rows, &s.BlksHit, &s.BlksRead, &s.Query); err != nil {
			return err
		}
		s.Key = s.Database + "/" + s.QueryID
		rows = append(rows, s)
		return nil
	})
	if err != nil {
		return err
	}
	for _, s := range d.Observe(rows, dbm.MaxStatements) {
		// db.query.hash is the canonical hash of the normalized text (sqlnorm.go, matches the
		// span side); pg_stat_statements already masks literals to $N, so this joins to spans.
		a := map[string]string{"database": s.Database, "queryid": s.QueryID, "query": dbm.BindSafe(s.Query),
			"db.query.hash": dbm.QueryHash(s.Query, true)}
		out.Sum("postgresql.query.calls", "{calls}", float64(s.Calls), a, now)
		out.Sum("postgresql.query.total_time", "ms", s.TotalMs, a, now)
		out.Sum("postgresql.query.rows", "{rows}", float64(s.Rows), a, now)
		out.Sum("postgresql.query.blks_hit", "{blocks}", float64(s.BlksHit), a, now)
		out.Sum("postgresql.query.blks_read", "{blocks}", float64(s.BlksRead), a, now)
		out.Gauge("postgresql.query.mean_time", "ms", s.MeanMs, a, now)
	}
	return nil
}

// runSamples samples pg_stat_activity every second on one long-lived read-only connection
// until ctx ends, reconnecting after a failure.
func runSamples(ctx context.Context, c *PostgresConfig, out sink.Sink) {
	fn := c.ExplainFunction
	if fn == "" {
		fn = defaultExplain
	}
	explained := map[string]time.Time{}
	for ctx.Err() == nil {
		err := sampleSession(ctx, c.DSN, c.Explain, fn, explained, out)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("postgres activity sampling failed", "error", sink.Truncate(errString(err), 300))
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
}

func errString(err error) string {
	if err == nil {
		return "connection closed"
	}
	return err.Error()
}

func sampleSession(ctx context.Context, dsn string, explain bool, fn string, explained map[string]time.Time,
	out sink.Sink,
) error {
	conn, err := pgConn(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var ver int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&ver); err != nil {
		return err
	}
	qid := "''" // pg_stat_activity.query_id is PostgreSQL 14+
	if ver >= 140000 {
		qid = "COALESCE(query_id::text, '')"
	}
	sql := `SELECT COALESCE(datname, ''), COALESCE(state, ''), COALESCE(wait_event_type, ''),
		COALESCE(wait_event, ''), ` + qid + `, COALESCE(query, ''),
		COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - query_start) * 1000, 0)::float8
		FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND backend_type = 'client backend'
		AND state IS DISTINCT FROM 'idle'`
	canExplain := false
	if explain {
		_ = conn.QueryRow(ctx, "SELECT to_regproc($1) IS NOT NULL", fn).Scan(&canExplain)
	}
	var s dbm.Sampler
	// hashSink stamps db.query.hash on the sample and plan log records (same mechanism as the
	// shared sampler in dbsample.go) so they join to spans; postgres is a pg dialect.
	hs := &hashSink{Sink: out, pg: true, raw: map[string]string{}}
	t := time.NewTicker(sampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		var rows []dbm.Activity
		err := each(ctx, conn, sql, func(r pgx.Rows) error {
			var a dbm.Activity
			if err := r.Scan(&a.Database, &a.State, &a.WaitType, &a.Wait, &a.QueryID, &a.Query, &a.DurationMs); err != nil {
				return err
			}
			rows = append(rows, a)
			return nil
		})
		if err != nil {
			return err
		}
		s.Add(rows)
		for _, a := range rows {
			if len(hs.raw) < 10*dbm.MaxSampleGroups {
				hs.raw[dbm.BindSafe(a.Query)] = a.Query
			}
		}
		if s.Ticks() < sampleFlush {
			continue
		}
		now := time.Now()
		cands := s.Flush(hs, "postgresql", now)
		if canExplain {
			explainSamples(ctx, conn, fn, cands, explained, hs, now)
		}
		clear(hs.raw)
	}
}

// explainSamples plans up to explainPerRound statements not planned in the last explainPerSig.
func explainSamples(ctx context.Context, conn *pgx.Conn, fn string, cands []dbm.Candidate,
	explained map[string]time.Time, out sink.Sink, now time.Time,
) {
	for k, at := range explained {
		if now.Sub(at) > explainPerSig {
			delete(explained, k)
		}
	}
	n := 0
	for _, c := range cands {
		if n >= explainPerRound || len(explained) >= 10_000 {
			return
		}
		if _, done := explained[c.Query]; done || !explainable(c.Raw) {
			continue
		}
		explained[c.Query] = now // failures too: a statement that cannot be planned is not retried
		n++
		var plan string
		// fn matched explainFnRE; the statement is a bound parameter, run by the function.
		if err := conn.QueryRow(ctx, "SELECT "+fn+"($1)::text", c.Raw).Scan(&plan); err != nil {
			continue
		}
		if p := dbm.ObfuscatePlan(plan); p != "" {
			EmitPlan(out, "postgresql", c.QueryID, c.Query, p, now)
		}
	}
}
