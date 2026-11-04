package integrations

// Postgres-backed job frameworks. Each query answers rows of (queue, state, count, oldest age in
// seconds); jqEmit.row routes them. {schema} is the quoted schema, {stall} the stall_after
// seconds. The session is read-only and in UTC, so the Rails and Oban `timestamp without time
// zone` columns (UTC by convention) compare correctly with now().

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// pgJobs returns a collector that runs queries against the framework's database.
func pgJobs(queries ...string) func(context.Context, *JobQueueConfig, *jqEmit) error {
	return func(ctx context.Context, c *JobQueueConfig, e *jqEmit) error {
		cfg, err := pgx.ParseConfig(c.DSN)
		if err != nil {
			return err
		}
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
		cfg.RuntimeParams["timezone"] = "UTC"
		conn, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return err
		}
		defer conn.Close(context.Background())
		r := jqSQL(c)
		for _, q := range queries {
			if err := each(ctx, conn, r.Replace(q), func(rows pgx.Rows) error {
				var queue, state string
				var n, age float64
				if err := rows.Scan(&queue, &state, &n, &age); err != nil {
					return err
				}
				if queue == "*" || c.want(queue) {
					e.row(queue, state, n, age)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}
}

// jqSQL fills the {schema} and {stall} placeholders. The schema is quoted as an identifier and
// stall is a number, so nothing from the config reaches the SQL text unescaped.
func jqSQL(c *JobQueueConfig) *strings.Replacer {
	schema := pgx.Identifier{c.Schema}.Sanitize()
	if jobFrameworks[c.framework].backend == "mssql" {
		schema = "[" + strings.ReplaceAll(c.Schema, "]", "]]") + "]"
	}
	return strings.NewReplacer("{schema}", schema, "{stall}", strconv.Itoa(int(c.stall.Seconds())))
}

// jqAge is the oldest-age column over a ready-at expression.
const jqAge = `COALESCE(EXTRACT(EPOCH FROM now() - min(ready)), 0)::float8`

func init() {
	// pg-boss (Node): {schema}.job. v10+ names the column start_after, v9 startafter; to_jsonb
	// reads whichever exists. created/retry/active/failed/cancelled; failed = retries exhausted.
	jobFrameworks["pgboss"] = jobFramework{backend: "pg", def: "pgboss", collect: pgJobs(`
		SELECT name, s, count(*)::float8, ` + jqAge + ` FROM (
		  SELECT name, ready, CASE st
		    WHEN 'created' THEN CASE WHEN ready > now() THEN 'scheduled' ELSE 'waiting' END
		    WHEN 'retry' THEN 'retry' WHEN 'active' THEN 'active' WHEN 'failed' THEN 'dead' ELSE st END AS s
		  FROM (SELECT j.name, j.state::text AS st,
		    COALESCE(to_jsonb(j)->>'start_after', to_jsonb(j)->>'startafter')::timestamptz AS ready
		    FROM {schema}.job j WHERE j.state::text <> 'completed') j) j
		GROUP BY name, s`)}
}

func init() {
	// Graphile Worker (Node): the {schema}.jobs view (a table before 0.16). The queue label is
	// the task identifier; named queues only serialize jobs. A lock older than stall_after is a
	// stalled job (Graphile itself frees locks after 4 hours).
	jobFrameworks["graphile_worker"] = jobFramework{backend: "pg", def: "graphile_worker", collect: pgJobs(`
		SELECT task_identifier, s, count(*)::float8, ` + jqAge + ` FROM (
		  SELECT task_identifier, run_at AS ready, CASE
		    WHEN locked_at IS NOT NULL AND locked_at > now() - interval '4 hours' THEN 'active'
		    WHEN attempts >= max_attempts THEN 'dead'
		    WHEN run_at > now() THEN CASE WHEN attempts > 0 THEN 'retry' ELSE 'scheduled' END
		    ELSE 'waiting' END AS s
		  FROM {schema}.jobs) j
		GROUP BY 1, 2
		UNION ALL
		SELECT task_identifier, 'stalled', count(*)::float8, 0 FROM {schema}.jobs
		WHERE locked_at < now() - make_interval(secs => {stall}) GROUP BY 1`)}
}

func init() {
	// Oban (Elixir): {schema}.oban_jobs (schema = Oban's prefix). executing jobs attempted longer
	// than stall_after ago are stalled (orphans that Oban's Lifeline plugin would rescue).
	jobFrameworks["oban"] = jobFramework{backend: "pg", def: "public", collect: pgJobs(`
		SELECT queue, CASE state::text WHEN 'available' THEN 'waiting' WHEN 'executing' THEN 'active'
		    WHEN 'retryable' THEN 'retry' WHEN 'discarded' THEN 'dead' ELSE state::text END,
		  count(*)::float8, COALESCE(EXTRACT(EPOCH FROM now() - min(scheduled_at)), 0)::float8
		FROM {schema}.oban_jobs WHERE state <> 'completed' GROUP BY queue, state
		UNION ALL
		SELECT queue, 'stalled', count(*)::float8, 0 FROM {schema}.oban_jobs
		WHERE state = 'executing' AND attempted_at < now() - make_interval(secs => {stall}) GROUP BY queue`)}
}

func init() {
	// River (Go): {schema}.river_job. running jobs attempted longer than stall_after ago are
	// stalled (River's rescuer retries them after its own RescueStuckJobsAfter, default 1h).
	jobFrameworks["river"] = jobFramework{backend: "pg", def: "public", collect: pgJobs(`
		SELECT queue, CASE state::text WHEN 'available' THEN 'waiting' WHEN 'running' THEN 'active'
		    WHEN 'retryable' THEN 'retry' WHEN 'discarded' THEN 'dead' ELSE state::text END,
		  count(*)::float8, COALESCE(EXTRACT(EPOCH FROM now() - min(scheduled_at)), 0)::float8
		FROM {schema}.river_job WHERE state <> 'completed' GROUP BY queue, state
		UNION ALL
		SELECT queue, 'stalled', count(*)::float8, 0 FROM {schema}.river_job
		WHERE state = 'running' AND attempted_at < now() - make_interval(secs => {stall}) GROUP BY queue`)}
}

func init() {
	// GoodJob (Rails): {schema}.good_jobs. Finished with an error = discarded (dead); performed
	// but not finished = running; an error on an unfinished job = waiting for its retry.
	jobFrameworks["good_job"] = jobFramework{backend: "pg", def: "public", collect: pgJobs(`
		SELECT q, s, count(*)::float8, ` + jqAge + ` FROM (
		  SELECT COALESCE(queue_name, 'default') AS q, COALESCE(scheduled_at, created_at) AS ready, CASE
		    WHEN finished_at IS NOT NULL THEN 'dead'
		    WHEN performed_at IS NOT NULL THEN 'active'
		    WHEN COALESCE(scheduled_at, created_at) > now() THEN CASE WHEN error IS NOT NULL THEN 'retry' ELSE 'scheduled' END
		    ELSE 'waiting' END AS s
		  FROM {schema}.good_jobs WHERE finished_at IS NULL OR error IS NOT NULL) j
		GROUP BY 1, 2
		UNION ALL
		SELECT COALESCE(queue_name, 'default'), 'stalled', count(*)::float8, 0 FROM {schema}.good_jobs
		WHERE finished_at IS NULL AND performed_at < now() - make_interval(secs => {stall}) GROUP BY 1`)}
}

func init() {
	// Solid Queue (Rails 8): one table per execution state. A claimed execution whose process
	// is gone or silent for 5 minutes (Solid Queue's process_alive_threshold) is stalled.
	jobFrameworks["solid_queue"] = jobFramework{backend: "pg", def: "public", collect: pgJobs(`
		SELECT queue_name, 'waiting', count(*)::float8, COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0)::float8
		  FROM {schema}.solid_queue_ready_executions GROUP BY 1
		UNION ALL SELECT queue_name, 'scheduled', count(*)::float8, 0 FROM {schema}.solid_queue_scheduled_executions GROUP BY 1
		UNION ALL SELECT queue_name, 'blocked', count(*)::float8, 0 FROM {schema}.solid_queue_blocked_executions GROUP BY 1
		UNION ALL SELECT j.queue_name, 'active', count(*)::float8, 0 FROM {schema}.solid_queue_claimed_executions c
		  JOIN {schema}.solid_queue_jobs j ON j.id = c.job_id GROUP BY 1
		UNION ALL SELECT j.queue_name, 'dead', count(*)::float8, 0 FROM {schema}.solid_queue_failed_executions f
		  JOIN {schema}.solid_queue_jobs j ON j.id = f.job_id GROUP BY 1
		UNION ALL SELECT j.queue_name, 'stalled', count(*)::float8, 0 FROM {schema}.solid_queue_claimed_executions c
		  JOIN {schema}.solid_queue_jobs j ON j.id = c.job_id LEFT JOIN {schema}.solid_queue_processes p ON p.id = c.process_id
		  WHERE p.id IS NULL OR p.last_heartbeat_at < now() - interval '5 minutes' GROUP BY 1
		UNION ALL SELECT '*', 'workers', count(*)::float8, 0 FROM {schema}.solid_queue_processes
		  WHERE kind = 'Worker' AND last_heartbeat_at > now() - interval '5 minutes'`)}
}

func init() {
	// Que 1.x/2.x (Rails): {schema}.que_jobs. A worker holds pg_try_advisory_lock(job id) while
	// it runs a job, so a granted advisory lock on the id (classid = high 32 bits, objid = low
	// 32 bits, objsubid 1) means active. expired_at = retries exhausted (dead).
	jobFrameworks["que"] = jobFramework{backend: "pg", def: "public", collect: pgJobs(`
		SELECT queue, s, count(*)::float8, ` + jqAge + ` FROM (
		  SELECT j.queue, j.run_at AS ready, CASE
		    WHEN j.expired_at IS NOT NULL THEN 'dead'
		    WHEN l.objid IS NOT NULL THEN 'active'
		    WHEN j.run_at > now() THEN CASE WHEN j.error_count > 0 THEN 'retry' ELSE 'scheduled' END
		    ELSE 'waiting' END AS s
		  FROM {schema}.que_jobs j
		  LEFT JOIN pg_locks l ON l.locktype = 'advisory' AND l.granted AND l.objsubid = 1
		    AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
		    AND ((l.classid::bigint << 32) | l.objid::bigint) = j.id
		  WHERE j.finished_at IS NULL) j
		GROUP BY 1, 2
		UNION ALL
		SELECT '*', 'workers', COALESCE(sum(worker_count), 0)::float8, 0 FROM {schema}.que_lockers`)}
}
