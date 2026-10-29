package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// PostgresConfig is the postgres module's config. DSN is local-file only (it carries the
// password); remote config may set Enabled and Interval.
type PostgresConfig struct {
	Base
	DSN string `json:"dsn"`
}

func (c *PostgresConfig) check() error {
	if c.DSN == "" {
		return errors.New("postgres: dsn is required (in the agent's own config file)")
	}
	return nil
}

// XIDWarnAge is the transaction-ID age at which wraparound becomes urgent (INF-027): the
// default freeze limit is 2e9, so 1.5e9 leaves a quarter of the runway to act.
const XIDWarnAge = 1.5e9

// Postgres collects pg_stat_database, replication lag, XID age, dead tuples, WAL archiving
// failures and the top 50 statements by total time (when pg_stat_statements is installed).
func Postgres(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &PostgresConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "postgres", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		return CollectPostgres(ctx, c.DSN, out, now)
	})
}

// CollectPostgres runs one round against dsn.
func CollectPostgres(ctx context.Context, dsn string, out sink.Sink, now time.Time) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return err
	}
	// Monitoring never writes: the session itself is read-only even if the role could write.
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	db := func(name string) map[string]string { return map[string]string{"database": name} }

	rows, err := conn.Query(ctx, `SELECT datname, numbackends, xact_commit, xact_rollback, blks_read,
		blks_hit, deadlocks, temp_bytes FROM pg_stat_database WHERE datname IS NOT NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		var backends int32
		var commit, rollback, read, hit, dead, temp int64
		if err := rows.Scan(&n, &backends, &commit, &rollback, &read, &hit, &dead, &temp); err != nil {
			rows.Close()
			return err
		}
		out.Gauge("postgresql.backends", "{connections}", float64(backends), db(n), now)
		out.Sum("postgresql.commits", "{transactions}", float64(commit), db(n), now)
		out.Sum("postgresql.rollbacks", "{transactions}", float64(rollback), db(n), now)
		out.Sum("postgresql.blks_read", "{blocks}", float64(read), db(n), now)
		out.Sum("postgresql.blks_hit", "{blocks}", float64(hit), db(n), now)
		out.Sum("postgresql.deadlocks", "{deadlocks}", float64(dead), db(n), now)
		out.Sum("postgresql.temp_bytes", "By", float64(temp), db(n), now)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if err := each(ctx, conn, `SELECT datname, age(datfrozenxid)::float8 FROM pg_database WHERE datallowconn`,
		func(r pgx.Rows) error {
			var n string
			var age float64
			if err := r.Scan(&n, &age); err != nil {
				return err
			}
			out.Gauge("postgresql.database.xid_age", "{transactions}", age, db(n), now)
			return nil
		}); err != nil {
		return err
	}
	// A primary lists its standbys; a standby reports its own replay delay.
	_ = each(ctx, conn, `SELECT COALESCE(application_name,''), COALESCE(EXTRACT(EPOCH FROM replay_lag),0)::float8
		FROM pg_stat_replication`, func(r pgx.Rows) error {
		var app string
		var lag float64
		if err := r.Scan(&app, &lag); err != nil {
			return err
		}
		out.Gauge("postgresql.replication.lag", "s", lag, map[string]string{"replica": app}, now)
		return nil
	})
	_ = each(ctx, conn, `SELECT EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())::float8
		WHERE pg_is_in_recovery() AND pg_last_xact_replay_timestamp() IS NOT NULL`, func(r pgx.Rows) error {
		var lag float64
		if err := r.Scan(&lag); err != nil {
			return err
		}
		out.Gauge("postgresql.replication.lag", "s", lag, map[string]string{"replica": "self"}, now)
		return nil
	})
	// Dead tuples and autovacuum age of the 50 worst tables of the connected database.
	_ = each(ctx, conn, `SELECT schemaname || '.' || relname, n_dead_tup, n_live_tup,
		COALESCE(EXTRACT(EPOCH FROM now() - GREATEST(last_autovacuum, last_vacuum)), -1)::float8
		FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 50`, func(r pgx.Rows) error {
		var n string
		var dead, live int64
		var vacAge float64
		if err := r.Scan(&n, &dead, &live, &vacAge); err != nil {
			return err
		}
		a := map[string]string{"table": n}
		out.Gauge("postgresql.table.dead_tuples", "{tuples}", float64(dead), a, now)
		out.Gauge("postgresql.table.live_tuples", "{tuples}", float64(live), a, now)
		if vacAge >= 0 {
			out.Gauge("postgresql.table.vacuum_age", "s", vacAge, a, now)
		}
		return nil
	})
	_ = each(ctx, conn, `SELECT failed_count, archived_count FROM pg_stat_archiver`, func(r pgx.Rows) error {
		var failed, ok int64
		if err := r.Scan(&failed, &ok); err != nil {
			return err
		}
		out.Sum("postgresql.wal.archive_failures", "{files}", float64(failed), nil, now)
		out.Sum("postgresql.wal.archived", "{files}", float64(ok), nil, now)
		return nil
	})
	// pg_stat_statements is optional; PG 13+ names the column total_exec_time.
	_ = each(ctx, conn, `SELECT queryid::text, left(regexp_replace(query, '\s+', ' ', 'g'), 120), calls,
		total_exec_time::float8, rows FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 50`,
		func(r pgx.Rows) error {
			var id, q string
			var calls, nrows int64
			var total float64
			if err := r.Scan(&id, &q, &calls, &total, &nrows); err != nil {
				return err
			}
			a := map[string]string{"queryid": id, "query": q}
			out.Sum("postgresql.statement.calls", "{calls}", float64(calls), a, now)
			out.Sum("postgresql.statement.total_time", "ms", total, a, now)
			out.Sum("postgresql.statement.rows", "{rows}", float64(nrows), a, now)
			return nil
		})
	// Blocked sessions and the sessions blocking them (lock/wait chains).
	var sessions []dbm.Session
	_ = each(ctx, conn, `SELECT pid, COALESCE(pg_blocking_pids(pid), '{}'), COALESCE(state,''),
		COALESCE(wait_event_type || ':' || wait_event, ''), COALESCE(query,''),
		COALESCE(EXTRACT(EPOCH FROM now() - COALESCE(query_start, xact_start)) * 1000, 0)::float8
		FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname IS NOT NULL`, func(r pgx.Rows) error {
		var s dbm.Session
		var by []int32
		if err := r.Scan(&s.PID, &by, &s.State, &s.WaitEvent, &s.Query, &s.AgeMs); err != nil {
			return err
		}
		for _, b := range by {
			s.BlockedBy = append(s.BlockedBy, int(b))
		}
		sessions = append(sessions, s)
		return nil
	})
	dbm.Report(out, "postgresql", sessions, now)
	return nil
}

func each(ctx context.Context, conn *pgx.Conn, sql string, f func(pgx.Rows) error) error {
	rows, err := conn.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := f(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
