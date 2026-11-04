package integrations

// Job frameworks (track B2): one module per framework reads the framework's own store (Postgres
// tables, Redis keys, SQL Server tables or an HTTP API) and reports the shared `job_queue_*`
// family with a `framework` label, so every framework lands on the same Queues page and alerts:
//
//	job_queue_jobs{framework,queue,state}               waiting|active|scheduled|retry|dead (+ framework extras)
//	job_queue_oldest_waiting_age_seconds{framework,queue}
//	job_queue_stalled_jobs{framework,queue}             running past the framework's lease or stall_after
//	job_queue_workers{framework,queue}                  live worker processes ("*" when not per queue)
//	job_queue_processed_total / job_queue_failed_total  where the store keeps counters
//
// The shape follows the bullmq module (bullmq_jobs{state}, ..._oldest_waiting_age_seconds).
// Completed jobs are never counted: stores keep them for days and counting them scans history.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// JobQueueConfig is the config of every job framework module. DSN, Addr, Password and Token are
// local-file only.
type JobQueueConfig struct {
	Base
	DSN           string   `json:"dsn"`  // Postgres (postgres://...) or SQL Server (sqlserver://...)
	Addr          string   `json:"addr"` // Redis or Faktory host:port
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	TLS           bool     `json:"tls"`
	DB            int      `json:"db"`             // Redis database number
	Prefix        string   `json:"prefix"`         // Redis key prefix (framework default when empty)
	HorizonPrefix string   `json:"horizon_prefix"` // Laravel Horizon's own key prefix
	Schema        string   `json:"schema"`         // SQL schema of the framework's tables
	URL           string   `json:"url"`            // Temporal HTTP API
	Token         string   `json:"token"`          // Temporal API key
	Namespace     string   `json:"namespace"`      // Temporal namespace
	Queues        []string `json:"queues"`         // filter; required where the store has no queue registry
	StallAfter    string   `json:"stall_after"`    // a running job older than this is stalled (default 1h)

	framework string
	stall     time.Duration
}

// jobFramework says where a framework keeps its jobs and how to read them.
type jobFramework struct {
	backend    string // pg, redis, mssql, faktory, http
	def        string // default schema (pg, mssql) or key prefix (redis)
	needQueues bool   // the store has no list of queues
	collect    func(ctx context.Context, c *JobQueueConfig, e *jqEmit) error
}

// jobFrameworks is the registry; each module name is also the manifest name.
var jobFrameworks = map[string]jobFramework{}

// JobFrameworks lists the job framework module names, sorted.
func JobFrameworks() []string {
	out := make([]string, 0, len(jobFrameworks))
	for k := range jobFrameworks {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c *JobQueueConfig) check() error {
	f, ok := jobFrameworks[c.framework]
	if !ok {
		return fmt.Errorf("unknown job framework %q", c.framework)
	}
	p := c.framework + ": "
	switch f.backend {
	case "pg":
		if c.DSN == "" {
			return errors.New(p + "dsn (postgres://...) is required (in the agent's own config file)")
		}
	case "mssql":
		if !strings.HasPrefix(c.DSN, "sqlserver://") {
			return errors.New(p + "dsn (sqlserver://...) is required (in the agent's own config file)")
		}
	case "redis", "faktory":
		if c.Addr == "" {
			return errors.New(p + "addr (host:port) is required (in the agent's own config file)")
		}
	case "http":
		if !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
			return errors.New(p + "url (http or https) is required (in the agent's own config file)")
		}
		c.URL = strings.TrimRight(c.URL, "/")
	}
	if f.needQueues && len(c.Queues) == 0 {
		return errors.New(p + "queues is required (the store keeps no list of queues)")
	}
	if len(c.Queues) > 100 {
		return errors.New(p + "at most 100 queues")
	}
	for _, q := range c.Queues {
		if q == "" || strings.ContainsAny(q, " \t\r\n/?#") {
			return fmt.Errorf("%squeue name %q is empty or has whitespace, / ? or #", p, q)
		}
	}
	if c.DB < 0 {
		return errors.New(p + "db must be 0 or more")
	}
	c.stall = time.Hour
	if c.StallAfter != "" {
		d, err := time.ParseDuration(c.StallAfter)
		if err != nil || d < time.Minute {
			return errors.New(p + "stall_after must be a duration of at least 1m")
		}
		c.stall = d
	}
	if c.Schema == "" && (f.backend == "pg" || f.backend == "mssql") {
		c.Schema = f.def
	}
	if c.Prefix == "" && f.backend == "redis" {
		c.Prefix = f.def
	}
	if c.Namespace == "" {
		c.Namespace = "default"
	}
	return nil
}

// want reports whether queue q is collected (all queues when no filter is set).
func (c *JobQueueConfig) want(q string) bool {
	if len(c.Queues) == 0 {
		return true
	}
	for _, w := range c.Queues {
		if w == q {
			return true
		}
	}
	return false
}

// queues is the configured list, or the store's own list filtered by it, sorted.
func (c *JobQueueConfig) queues(found []string) []string {
	if len(found) == 0 && len(c.Queues) > 0 {
		found = c.Queues
	}
	var out []string
	for _, q := range found {
		if c.want(q) {
			out = append(out, q)
		}
	}
	sort.Strings(out)
	return out
}

// JobQueue returns the module of one job framework.
func JobQueue(fw string) func(context.Context, json.RawMessage, sink.Sink) error {
	return func(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
		c := &JobQueueConfig{framework: fw}
		if err := load(raw, c); err != nil {
			return err
		}
		f := jobFrameworks[fw]
		seen := map[string]map[string]string{}
		return Loop(ctx, fw, c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
			e := &jqEmit{out: out, fw: fw, now: now, seen: seen, got: map[string]bool{}}
			if err := f.collect(ctx, c, e); err != nil {
				return err
			}
			e.finish()
			return nil
		})
	}
}

// maxJobQueues bounds the series one module can create.
const maxJobQueues = 200

// jqEmit writes the job_queue_* family for one round. Every series a queue ever had is written
// each round (0 when the store no longer reports it), so a drained queue reads 0, not stale.
type jqEmit struct {
	out  sink.Sink
	fw   string
	now  time.Time
	seen map[string]map[string]string // queue -> name\x00state -> unit, across rounds
	got  map[string]bool              // queue\x00name\x00state written this round
}

func (e *jqEmit) gauge(name, unit, q, state string, v float64) {
	if e.seen[q] == nil {
		if len(e.seen) >= maxJobQueues {
			return
		}
		e.seen[q] = map[string]string{}
	}
	key := name + "\x00" + state
	e.seen[q][key] = unit
	e.got[q+"\x00"+key] = true
	e.out.Gauge(name, unit, v, e.attrs(q, state), e.now)
}

func (e *jqEmit) attrs(q, state string) map[string]string {
	a := map[string]string{"framework": e.fw, "queue": q}
	if state != "" {
		a["state"] = state
	}
	return a
}

func (e *jqEmit) jobs(q, state string, n float64) { e.gauge("job_queue_jobs", "{jobs}", q, state, n) }
func (e *jqEmit) age(q string, s float64) {
	e.gauge("job_queue_oldest_waiting_age_seconds", "s", q, "", max(0, s))
}
func (e *jqEmit) stalled(q string, n float64) { e.gauge("job_queue_stalled_jobs", "{jobs}", q, "", n) }
func (e *jqEmit) workers(q string, n float64) { e.gauge("job_queue_workers", "{workers}", q, "", n) }

// total writes a cumulative counter the store keeps (processed, failed).
func (e *jqEmit) total(what, q string, n float64) {
	e.out.Sum("job_queue_"+what+"_total", "{jobs}", n, e.attrs(q, ""), e.now)
}

// row routes one (queue, state, count, oldest age) row of a SQL store: the pseudo states
// stalled, workers, processed and failed_total go to their own metrics; the age is the oldest
// waiting job's.
func (e *jqEmit) row(q, state string, n, age float64) {
	switch state {
	case "stalled":
		e.stalled(q, n)
	case "workers":
		e.workers(q, n)
	case "processed":
		e.total("processed", q, n)
	case "failed_total":
		e.total("failed", q, n)
	default:
		e.jobs(q, state, n)
		if state == "waiting" {
			e.age(q, age)
		}
	}
}

// finish writes 0 for every series seen before but not reported this round.
func (e *jqEmit) finish() {
	for q, keys := range e.seen {
		for key, unit := range keys {
			if e.got[q+"\x00"+key] {
				continue
			}
			name, state, _ := strings.Cut(key, "\x00")
			e.out.Gauge(name, unit, 0, e.attrs(q, state), e.now)
		}
	}
}
