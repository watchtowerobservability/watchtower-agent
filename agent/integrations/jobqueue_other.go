package integrations

// Job frameworks on SQL Server (Hangfire), their own server (Faktory) and an HTTP API (Temporal).

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// mssqlJobs is pgJobs for SQL Server: each query answers (queue, state, count, oldest age).
func mssqlJobs(queries ...string) func(context.Context, *JobQueueConfig, *jqEmit) error {
	return func(ctx context.Context, c *JobQueueConfig, e *jqEmit) error {
		db, err := sql.Open("sqlserver", c.DSN)
		if err != nil {
			return err
		}
		defer db.Close()
		r := jqSQL(c)
		for _, q := range queries {
			rows, err := db.QueryContext(ctx, r.Replace(q))
			if err != nil {
				return err
			}
			for rows.Next() {
				var queue, state string
				var n, age float64
				if err := rows.Scan(&queue, &state, &n, &age); err != nil {
					rows.Close()
					return err
				}
				if queue == "*" || c.want(queue) {
					e.row(queue, state, n, age)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		return nil
	}
}

func init() {
	// Hangfire (.NET) on SQL Server: JobQueue rows not yet fetched are waiting (age from the
	// Enqueued state's time), fetched ones are processing; Scheduled and Failed (retries
	// exhausted) jobs are counted for all queues; servers with a heartbeat in 5 minutes are the
	// workers; stats:succeeded (Counter plus AggregatedCounter) is the processed total.
	jobFrameworks["hangfire"] = jobFramework{backend: "mssql", def: "HangFire", collect: mssqlJobs(`
		SELECT q.Queue, CASE WHEN q.FetchedAt IS NULL THEN 'waiting' ELSE 'active' END,
		  CAST(COUNT_BIG(*) AS float), CAST(ISNULL(DATEDIFF(second, MIN(s.CreatedAt), SYSUTCDATETIME()), 0) AS float)
		FROM {schema}.JobQueue q
		LEFT JOIN {schema}.Job j ON j.Id = q.JobId LEFT JOIN {schema}.State s ON s.Id = j.StateId
		GROUP BY q.Queue, CASE WHEN q.FetchedAt IS NULL THEN 'waiting' ELSE 'active' END
		UNION ALL
		SELECT '*', CASE StateName WHEN 'Scheduled' THEN 'scheduled' ELSE 'dead' END, CAST(COUNT_BIG(*) AS float), 0.0
		FROM {schema}.Job WHERE StateName IN ('Scheduled', 'Failed') GROUP BY StateName
		UNION ALL
		SELECT '*', 'workers', CAST(COUNT_BIG(*) AS float), 0.0
		FROM {schema}.Server WHERE LastHeartbeat > DATEADD(minute, -5, SYSUTCDATETIME())
		UNION ALL
		SELECT '*', 'processed', CAST(ISNULL(SUM(CAST(Value AS bigint)), 0) AS float), 0.0 FROM (
		  SELECT Value FROM {schema}.Counter WHERE [Key] = 'stats:succeeded'
		  UNION ALL SELECT Value FROM {schema}.AggregatedCounter WHERE [Key] = 'stats:succeeded') c`)}
}

// faktoryHash is Faktory's password proof: sha256(password + salt), rehashed until iterations.
func faktoryHash(password, salt string, iterations int) string {
	h := sha256.Sum256([]byte(password + salt))
	for i := 1; i < iterations; i++ {
		h = sha256.Sum256(h[:])
	}
	return hex.EncodeToString(h[:])
}

// faktoryTalk does the client handshake (HI, HELLO with the password proof) and returns INFO.
func faktoryTalk(rw io.ReadWriter, password string) ([]byte, error) {
	r := bufio.NewReader(rw)
	v, err := jqRead(r, 0)
	hi, _ := v.(string)
	if err != nil || !strings.HasPrefix(hi, "HI ") {
		return nil, errors.New("faktory: no HI greeting")
	}
	var h struct {
		Salt       string `json:"s"`
		Iterations int    `json:"i"`
	}
	if err := json.Unmarshal([]byte(hi[3:]), &h); err != nil {
		return nil, errors.New("faktory: bad HI greeting")
	}
	host, _ := os.Hostname()
	hello := map[string]any{"v": 2, "hostname": host}
	if h.Salt != "" {
		if password == "" {
			return nil, errors.New("faktory: the server wants a password")
		}
		hello["pwdhash"] = faktoryHash(password, h.Salt, max(1, h.Iterations))
	}
	b, _ := json.Marshal(hello)
	if _, err := io.WriteString(rw, "HELLO "+string(b)+"\r\n"); err != nil {
		return nil, err
	}
	if v, err := jqRead(r, 0); err != nil || v != "OK" {
		return nil, errors.New("faktory: HELLO refused (password?)")
	}
	if _, err := io.WriteString(rw, "INFO\r\n"); err != nil {
		return nil, err
	}
	v, err = jqRead(r, 0)
	if err != nil {
		return nil, err
	}
	_, _ = io.WriteString(rw, "END\r\n")
	info, _ := v.(string)
	return []byte(info), nil
}

// emitFaktory reads INFO: queue sizes (waiting), the Busy, Scheduled, Retries and Dead sets
// (all queues), connected Workers and the processed and failure totals.
func emitFaktory(e *jqEmit, c *JobQueueConfig, info []byte) error {
	var i struct {
		Faktory struct {
			Processed float64            `json:"total_processed"`
			Failures  float64            `json:"total_failures"`
			Queues    map[string]float64 `json:"queues"`
			Tasks     map[string]struct {
				Size float64 `json:"size"`
			} `json:"tasks"`
		} `json:"faktory"`
	}
	if err := json.Unmarshal(info, &i); err != nil {
		return errors.New("faktory: INFO is not JSON")
	}
	f := i.Faktory
	names := make([]string, 0, len(f.Queues))
	for q := range f.Queues {
		names = append(names, q)
	}
	for _, q := range c.queues(names) {
		e.jobs(q, "waiting", f.Queues[q])
	}
	for task, state := range map[string]string{"Busy": "active", "Scheduled": "scheduled", "Retries": "retry", "Dead": "dead"} {
		e.jobs("*", state, f.Tasks[task].Size)
	}
	e.workers("*", f.Tasks["Workers"].Size)
	e.total("processed", "*", f.Processed)
	e.total("failed", "*", f.Failures)
	return nil
}

func init() {
	jobFrameworks["faktory"] = jobFramework{backend: "faktory", collect: func(ctx context.Context, c *JobQueueConfig, e *jqEmit) error {
		conn, err := dial(ctx, c.Addr, c.TLS)
		if err != nil {
			return err
		}
		defer conn.Close()
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(dl)
		}
		info, err := faktoryTalk(conn, c.Password)
		if err != nil {
			return err
		}
		return emitFaktory(e, c, info)
	}}
}

// temporalTaskQueue is the part of DescribeTaskQueue (HTTP API, protojson) that is read.
type temporalTaskQueue struct {
	Pollers []struct {
		Identity string `json:"identity"`
	} `json:"pollers"`
	Stats struct {
		Count any    `json:"approximateBacklogCount"` // int64: a JSON string in protojson
		Age   string `json:"approximateBacklogAge"`   // duration, "12.5s"
	} `json:"stats"`
}

// temporalTypes are the task queue kinds a worker polls; both share the queue's name.
var temporalTypes = []string{"TASK_QUEUE_TYPE_WORKFLOW", "TASK_QUEUE_TYPE_ACTIVITY"}

func init() {
	// Temporal: DescribeTaskQueue with reportStats through the frontend's HTTP API (port 7243,
	// or Temporal Cloud with an API key) per configured task queue, workflow and activity
	// summed: backlog (waiting), backlog age and distinct poller identities (workers).
	jobFrameworks["temporal"] = jobFramework{backend: "http", needQueues: true, collect: func(ctx context.Context, c *JobQueueConfig, e *jqEmit) error {
		hdr := map[string]string{"temporal-namespace": c.Namespace}
		if c.Token != "" {
			hdr["Authorization"] = "Bearer " + c.Token
		}
		for _, q := range c.queues(nil) {
			backlog, age, ids := 0.0, 0.0, map[string]bool{}
			for _, typ := range temporalTypes {
				var r temporalTaskQueue
				u := c.URL + "/api/v1/namespaces/" + url.PathEscape(c.Namespace) + "/task-queues/" + url.PathEscape(q) +
					"?taskQueueType=" + typ + "&reportStats=true"
				if err := doJSON(ctx, HTTPConfig{}, http.MethodGet, u, hdr, nil, &r); err != nil {
					return err
				}
				backlog += jqFloat(r.Stats.Count)
				if d, err := time.ParseDuration(r.Stats.Age); err == nil {
					age = max(age, d.Seconds())
				}
				for _, p := range r.Pollers {
					ids[p.Identity] = true
				}
			}
			e.jobs(q, "waiting", backlog)
			e.age(q, age)
			e.workers(q, float64(len(ids)))
		}
		return nil
	}}
}
