package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
)

// DestConfig is one entry of `destinations:`: an extra place the relay delivers every processed
// event, besides the gateway. Each destination has its own disk queue (`<queue.dir>/dest-<name>`)
// and delivers at least once: a batch is removed only after the destination accepted it, so a
// crash or retry can deliver it twice (S3 and Elasticsearch use deterministic object keys and
// document ids, so a repeat overwrites). Offered events are appended to that queue before the
// relay acks the sender, so a hard crash loses nothing that was acked; batches are formed when
// the queue is drained (Batch.MaxEvents, or Batch.MaxAge after the first event).
type DestConfig struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // s3, splunk_hec, elasticsearch, datadog
	URL  string `yaml:"url"`  // s3: endpoint (path-style); datadog: logs intake; others: base URL
	// SecretFile or SecretEnv (name of an env var) holds the credential: S3 secret key, Splunk HEC
	// token, Elasticsearch password or API key, Datadog API key.
	SecretFile string `yaml:"secret_file"`
	SecretEnv  string `yaml:"secret_env"`
	// OverflowOnly: receive only what a quota processor routed here (see StreamProc.Overflow).
	OverflowOnly bool `yaml:"overflow_only"`
	Batch        struct {
		MaxEvents int           `yaml:"max_events"` // default 500
		MaxAge    time.Duration `yaml:"max_age"`    // default 5s
	} `yaml:"batch"`

	Bucket    string `yaml:"bucket"`     // s3
	Region    string `yaml:"region"`     // s3
	AccessKey string `yaml:"access_key"` // s3 access key id; default env AWS_ACCESS_KEY_ID
	// SessionTokenFile or SessionTokenEnv holds an STS session token (default env AWS_SESSION_TOKEN).
	// The s3 secret key falls back to env AWS_SECRET_ACCESS_KEY. No IMDS or profile lookups.
	SessionTokenFile string `yaml:"session_token_file"`
	SessionTokenEnv  string `yaml:"session_token_env"`
	Prefix           string `yaml:"prefix"` // s3 key prefix

	Index      string `yaml:"index"`      // splunk index; elasticsearch index pattern (%Y %m %d), default watchtower-%Y.%m.%d
	Source     string `yaml:"source"`     // splunk
	Sourcetype string `yaml:"sourcetype"` // splunk
	Username   string `yaml:"username"`   // elasticsearch basic auth; without it the secret is an API key

	Site       string `yaml:"site"`        // datadog site, default datadoghq.com
	MetricsURL string `yaml:"metrics_url"` // datadog series endpoint override
	TracesURL  string `yaml:"traces_url"`  // datadog trace intake override (default https://trace.agent.<site>/api/v0.2/traces)
	Hostname   string `yaml:"hostname"`    // datadog host tag
}

var destName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

func (c *Config) validateDestinations() error {
	names := map[string]bool{}
	for i, d := range c.Destinations {
		if !destName.MatchString(d.Name) || names[d.Name] {
			return fmt.Errorf("destinations[%d]: name %q must be unique, lowercase letters, digits, - or _", i, d.Name)
		}
		names[d.Name] = true
		if _, err := newSender(d, nil, ""); err != nil {
			return fmt.Errorf("destinations[%s]: %w", d.Name, err)
		}
		if d.URL != "" {
			if err := c.checkURL("destinations["+d.Name+"].url", d.URL, false); err != nil {
				return err
			}
		}
	}
	for i, p := range c.StreamProcessors {
		if _, err := compileStream(i, p); err != nil {
			return err
		}
		if p.Overflow != "" && !names[p.Overflow] {
			return fmt.Errorf("stream_processors[%d]: overflow destination %q is not defined", i, p.Overflow)
		}
	}
	return nil
}

// sender delivers one batch. A *permError is dropped and counted; a *retryError or any other
// error is retried with backoff.
type sender interface {
	send(ctx context.Context, evs []Event) error
}

type permError struct{ err error }

func (e *permError) Error() string { return e.err.Error() }

// Dests fans processed events out to the destinations.
type Dests struct {
	procs []streamProc
	dests []*destination
	by    map[string]*destination
}

type destination struct {
	cfg  DestConfig
	snd  sender
	q    *Queue
	poke chan struct{}

	mu    sync.Mutex
	n     int // events queued since the last drain started
	since time.Time
	fails int

	sent, rejected, retried atomic.Int64
	sleep                   func(ctx context.Context, d time.Duration) error // tests replace it
}

const maxBatchBytes = 4 << 20 // stays under the 8 MiB queue record limit

// StartDests opens the destination queues and starts one delivery goroutine each. It returns
// nil when nothing is configured.
func StartDests(ctx context.Context, cfg Config, client *http.Client) (*Dests, error) {
	if len(cfg.Destinations) == 0 {
		return nil, nil
	}
	ds := &Dests{by: map[string]*destination{}}
	for i, p := range cfg.StreamProcessors {
		sp, err := compileStream(i, p)
		if err != nil {
			return nil, err
		}
		ds.procs = append(ds.procs, sp)
	}
	for _, c := range cfg.Destinations {
		sec, err := secret(c.SecretEnv, c.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("destination %s: %w", c.Name, err)
		}
		if sec == "" && c.Type == "s3" {
			sec = os.Getenv("AWS_SECRET_ACCESS_KEY")
		}
		snd, err := newSender(c, client, sec)
		if err != nil {
			return nil, fmt.Errorf("destination %s: %w", c.Name, err)
		}
		q, err := OpenQueue(filepath.Join(cfg.Queue.Dir, "dest-"+c.Name), cfg.Queue.MaxBytes)
		if err != nil {
			return nil, fmt.Errorf("destination %s queue: %w", c.Name, err)
		}
		d := &destination{cfg: c, snd: snd, q: q, poke: make(chan struct{}, 1)}
		ds.dests, ds.by[c.Name] = append(ds.dests, d), d
		go d.run(ctx)
	}
	return ds, nil
}

// Offer runs the stream processors over one processed OTLP request and buffers the result.
func (ds *Dests) Offer(m proto.Message) {
	if ds == nil {
		return
	}
	evs := EventsOf(m)
	if len(evs) == 0 {
		return
	}
	over := map[string][]Event{}
	now := time.Now()
	for _, p := range ds.procs {
		evs = p.apply(evs, now, over)
	}
	for _, d := range ds.dests {
		if !d.cfg.OverflowOnly {
			d.add(evs)
		}
	}
	for name, e := range over {
		ds.by[name].add(e)
	}
}

// add appends evs to the destination's disk queue (chunked under the record limit) before
// returning, so the caller can ack its sender.
func (d *destination) add(evs []Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var chunk []json.RawMessage
	size := 0
	flush := func() {
		if len(chunk) == 0 {
			return
		}
		b, _ := json.Marshal(chunk)
		if err := d.q.Add("/events", b); err != nil {
			slog.Error("relay destination queue", "dest", d.cfg.Name, "error", err)
		} else {
			if d.n == 0 {
				d.since = time.Now()
			}
			d.n += len(chunk)
		}
		chunk, size = nil, 0
	}
	for _, e := range evs {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		chunk, size = append(chunk, b), size+len(b)
		if size >= maxBatchBytes {
			flush()
		}
	}
	flush()
	if d.n >= d.maxEvents() {
		select {
		case d.poke <- struct{}{}:
		default:
		}
	}
}

func (d *destination) maxEvents() int {
	if d.cfg.Batch.MaxEvents > 0 {
		return d.cfg.Batch.MaxEvents
	}
	return 500
}

// due reports whether a batch should be sent now: enough events, old enough, or retrying.
func (d *destination) due() bool {
	age := d.cfg.Batch.MaxAge
	if age <= 0 {
		age = 5 * time.Second
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fails > 0 || d.n == 0 || d.n >= d.maxEvents() || time.Since(d.since) >= age
}

// step drains the queue, coalescing records into batches of MaxEvents. A segment is removed only
// after all its records were accepted, so the final partial batch is sent inside the callback of
// the last record (found by counting); if the count was off, the leftover is sent after the drain
// and put back on the queue if that fails.
func (d *destination) step(ctx context.Context) error {
	d.mu.Lock()
	d.n = 0
	d.mu.Unlock()
	total := d.q.records()
	var pending []Event
	size, seen := 0, int64(0)
	err := d.q.Drain(func(_ string, body []byte) error {
		seen++
		var raw []json.RawMessage
		if json.Unmarshal(body, &raw) == nil {
			for _, r := range raw {
				var e Event
				if json.Unmarshal(r, &e) == nil {
					pending, size = append(pending, e), size+len(r)
				}
			}
		}
		if len(pending) < d.maxEvents() && size < maxBatchBytes && seen < total {
			return nil
		}
		if err := d.deliver(ctx, pending); err != nil {
			return err
		}
		pending, size = nil, 0
		return nil
	})
	if err == nil && len(pending) > 0 {
		if err = d.deliver(ctx, pending); err != nil {
			d.add(pending)
		}
	}
	return err
}

func (d *destination) deliver(ctx context.Context, evs []Event) error {
	err := d.snd.send(ctx, evs)
	var pe *permError
	switch {
	case err == nil:
		d.sent.Add(int64(len(evs)))
	case errors.As(err, &pe):
		slog.Error("relay destination rejected batch, dropped", "dest", d.cfg.Name, "error", err)
		d.rejected.Add(int64(len(evs)))
	default:
		d.retried.Add(1)
		return err
	}
	return nil
}

func (d *destination) run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		if !d.due() {
			select {
			case <-ctx.Done():
			case <-d.poke:
			case <-tick.C:
			}
			continue
		}
		if err := d.step(ctx); err != nil {
			d.mu.Lock()
			d.fails++
			d.mu.Unlock()
			wait := min(minBackoff<<min(d.fails-1, 10), maxBackoff)
			var re *retryError
			if errors.As(err, &re) && re.after > 0 {
				wait = min(re.after, maxRetryAfter)
			}
			wait -= time.Duration(rand.Int64N(int64(wait/5) + 1))
			slog.Warn("relay destination failed", "dest", d.cfg.Name, "error", err, "retry_in", wait)
			if d.wait(ctx, wait) != nil {
				break
			}
			continue
		}
		d.mu.Lock()
		d.fails = 0
		d.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-d.poke:
		case <-tick.C:
		}
	}
	_ = d.q.Close()
}

func (d *destination) wait(ctx context.Context, w time.Duration) error {
	if d.sleep != nil {
		return d.sleep(ctx, w)
	}
	t := time.NewTimer(w)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// WriteMetrics appends the destination and processor counters to the relay's /metrics page.
func (ds *Dests) WriteMetrics(w io.Writer) {
	if ds == nil {
		return
	}
	for _, d := range ds.dests {
		fmt.Fprintf(w, "wt_relay_dest_queue_depth{dest=%q} %d\nwt_relay_dest_dropped_total{dest=%q} %d\n", d.cfg.Name, d.q.Depth(), d.cfg.Name, d.q.Dropped())
		fmt.Fprintf(w, "wt_relay_dest_sent_events_total{dest=%q} %d\nwt_relay_dest_rejected_events_total{dest=%q} %d\nwt_relay_dest_retries_total{dest=%q} %d\n",
			d.cfg.Name, d.sent.Load(), d.cfg.Name, d.rejected.Load(), d.cfg.Name, d.retried.Load())
	}
	for _, p := range ds.procs {
		dr, ov := p.counts()
		fmt.Fprintf(w, "wt_relay_proc_dropped_events_total{proc=%q} %d\nwt_relay_proc_overflow_events_total{proc=%q} %d\n", p.label(), dr, p.label(), ov)
	}
}

// records is the number of records on disk (exact, unlike Depth after a failed drain).
func (q *Queue) records() int64 { return q.w.Count() }
