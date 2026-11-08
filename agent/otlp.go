package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/wal"
)

const (
	maxBuffered   = 20_000  // points and log records each; the oldest are dropped past this
	maxBufBytes   = 8 << 20 // estimated bytes buffered (points and logs together)
	chunkBytes    = 3 << 20 // estimated bytes per request, below maxBodyBytes after encoding
	maxBodyChars  = 256 << 10
	flushEvery    = 10 * time.Second
	flushAtLeast  = 2_000
	maxBodyBytes  = 4 << 20
	exportTimeout = 15 * time.Second
)

// Exporter is what modules write to. It is an ordinary OTLP/HTTP client of the gateway.
type Exporter interface {
	Gauge(name, unit string, value float64, attrs map[string]string, at time.Time)
	// Sum is a cumulative monotonic counter.
	Sum(name, unit string, value float64, attrs map[string]string, at time.Time)
	Log(severity, body string, attrs map[string]string, at time.Time)
}

type point struct {
	res        map[string]string // set only through ResourceSink (the k8s collectors)
	name, unit string
	sum        bool
	value      float64
	attrs      map[string]string
	at         time.Time
	size       int
	hist       *histPoint // set: a cumulative explicit-bucket histogram (value unused)
}

type histPoint struct {
	bounds []float64
	counts []uint64
	sum    float64
	count  uint64
}

type logRec struct {
	res            map[string]string
	severity, body string
	attrs          map[string]string
	at             time.Time
	size           int
}

// clean makes s valid UTF-8, which proto3 string fields require: one bad byte would otherwise
// make Marshal fail and drop the whole batch.
func clean(s string) string { return strings.ToValidUTF8(s, "\uFFFD") }

func cleanAttrs(m map[string]string) (map[string]string, int) {
	out := make(map[string]string, len(m))
	n := 0
	for k, v := range m {
		k, v = clean(k), clean(v)
		out[k] = v
		n += len(k) + len(v) + 8
	}
	return out, n
}

// OTLP batches samples and posts them to <Base>/v1/metrics and <Base>/v1/logs with the agent's
// `wti` token (scopes ingest:metrics and ingest:logs).
type OTLP struct {
	Base     string
	Token    string
	Resource map[string]string
	HTTP     *http.Client

	started time.Time
	// Buffer, when set, takes batches that could not be sent (retryable failures) and replays
	// them oldest first before new data; delivery stays at-least-once.
	Buffer *wal.WAL
	fails  int // consecutive failed flushes, for the retry backoff
	// Logs back off alone: a refused log batch (a daily quota can last hours) must not delay metrics.
	logFails int
	logsNext time.Time
	nextTry  time.Time  // Run does not flush before this
	flushMu  sync.Mutex // one Flush at a time, so a caller of Flush sees every earlier export settled
	mu       sync.Mutex
	points   []point
	logs     []logRec
	bytes    int // estimated size of points and logs
	dropped  int
	stats    exportStats // the agent's own export counters (otlp_self.go)
	spans    []spanBatch // ebpf_trace spans, see otlp_spans.go
	// Tee, when set, gets a copy of every marshalled batch (forward.go); it must not block.
	Tee func(path string, body []byte)
	// Enrich, when set, adds attributes to every point and log record (the enrich module).
	Enrich func(attrs map[string]string)
}

// NewOTLP builds an exporter. Resource attributes describe this host.
func NewOTLP(base, token string, res map[string]string) *OTLP {
	return &OTLP{
		Base: base, Token: token, Resource: res, started: time.Now(),
		HTTP: netguard.GuardedNoRedirect("agent", exportTimeout),
	}
}

func (o *OTLP) Gauge(name, unit string, v float64, a map[string]string, at time.Time) {
	o.addPoint(point{name: name, unit: unit, value: v, attrs: a, at: at})
}

func (o *OTLP) Sum(name, unit string, v float64, a map[string]string, at time.Time) {
	o.addPoint(point{name: name, unit: unit, sum: true, value: v, attrs: a, at: at})
}

// Histogram is a cumulative explicit-bucket histogram point; counts has len(bounds)+1 entries.
func (o *OTLP) Histogram(name, unit string, bounds []float64, counts []uint64, sum float64, count uint64, a map[string]string, at time.Time) {
	o.addPoint(point{name: name, unit: unit, attrs: a, at: at, hist: &histPoint{bounds: bounds, counts: counts, sum: sum, count: count}})
}

// GaugeRes is Gauge with resource attributes. Only modules that wrap their sink in Hoist (Kubernetes, virtualization, cloud, docker) reach it (through
// sink.Hoist); no attribute of any other module can name the resource.
func (o *OTLP) GaugeRes(name, unit string, v float64, res, a map[string]string, at time.Time) {
	o.addPoint(point{res: res, name: name, unit: unit, value: v, attrs: a, at: at})
}

// SumRes is Sum with resource attributes.
func (o *OTLP) SumRes(name, unit string, v float64, res, a map[string]string, at time.Time) {
	o.addPoint(point{res: res, name: name, unit: unit, sum: true, value: v, attrs: a, at: at})
}

func (o *OTLP) addPoint(p point) {
	var n, rn int
	p.name, p.unit = clean(p.name), clean(p.unit)
	p.attrs, n = cleanAttrs(p.attrs)
	if o.Enrich != nil {
		o.Enrich(p.attrs) // cleanAttrs made a copy
	}
	if len(p.res) > 0 {
		p.res, rn = cleanAttrs(p.res)
	}
	p.size = n + rn + len(p.name) + len(p.unit) + 48
	if p.hist != nil {
		p.size += 16 * len(p.hist.counts)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.points = append(o.points, p)
	o.bytes += p.size
	o.trim(true)
}

// trim drops the oldest records while the buffer is over its count or byte bounds. It drops from
// the list that just grew first.
func (o *OTLP) trim(points bool) {
	for len(o.points) > maxBuffered || len(o.logs) > maxBuffered || o.bytes > maxBufBytes {
		switch {
		case len(o.points) > 0 && (points || len(o.logs) == 0):
			o.bytes -= o.points[0].size
			o.points = o.points[1:]
		case len(o.logs) > 0:
			o.bytes -= o.logs[0].size
			o.logs = o.logs[1:]
		default:
			return
		}
		o.dropped++
	}
}

func (o *OTLP) Log(severity, body string, a map[string]string, at time.Time) {
	o.LogRes(severity, body, nil, a, at)
}

// LogRes is Log with resource attributes (see GaugeRes).
func (o *OTLP) LogRes(severity, body string, res, a map[string]string, at time.Time) {
	body = clean(sink.Truncate(body, maxBodyChars))
	a, n := cleanAttrs(a)
	if o.Enrich != nil {
		o.Enrich(a)
	}
	var rn int
	if len(res) > 0 {
		res, rn = cleanAttrs(res)
	}
	r := logRec{res: res, severity: clean(severity), body: body, attrs: a, at: at, size: n + rn + len(body) + 48}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.logs = append(o.logs, r)
	o.bytes += r.size
	o.trim(false)
}

func kvs(m map[string]string) []*commonpb.KeyValue {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*commonpb.KeyValue, 0, len(keys))
	for _, k := range keys {
		out = append(out, &commonpb.KeyValue{Key: clean(k), Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: clean(m[k])}}})
	}
	return out
}

// resourceWith is the agent's own resource plus extra attributes (which win).
func (o *OTLP) resourceWith(extra map[string]string) *resourcepb.Resource {
	if len(extra) == 0 {
		return &resourcepb.Resource{Attributes: kvs(o.Resource)}
	}
	return &resourcepb.Resource{Attributes: kvs(sink.With(o.Resource, flatKV(extra)...))}
}

func flatKV(m map[string]string) []string {
	kv := make([]string, 0, 2*len(m))
	for k, v := range m {
		kv = append(kv, k, v)
	}
	return kv
}

// resKey is a stable identity for a resource attribute set.
func resKey(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(m[k])
		b.WriteByte(0)
	}
	return b.String()
}

// MetricsRequest builds the OTLP request for the points (exported for tests). Points that carry
// resource attributes (GaugeRes) are grouped into one ResourceMetrics per distinct set.
func (o *OTLP) MetricsRequest(pts []point) *colmetrics.ExportMetricsServiceRequest {
	type key struct {
		res, name string
		sum, hist bool
	}
	type group struct {
		res     map[string]string
		metrics []*metricspb.Metric
	}
	byName := map[key]*metricspb.Metric{}
	groups := map[string]*group{"": {}}
	order := []string{""}
	for _, p := range pts {
		res, attrs := p.res, p.attrs
		rk := resKey(res)
		g := groups[rk]
		if g == nil {
			g = &group{res: res}
			groups[rk] = g
			order = append(order, rk)
		}
		k := key{rk, p.name, p.sum, p.hist != nil}
		m := byName[k]
		if m == nil {
			m = &metricspb.Metric{Name: p.name, Unit: p.unit}
			switch {
			case p.hist != nil:
				m.Data = &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
					AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				}}
			case p.sum:
				m.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
					AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
					IsMonotonic:            true,
				}}
			default:
				m.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{}}
			}
			byName[k] = m
			g.metrics = append(g.metrics, m)
		}
		if h := p.hist; h != nil {
			sum := h.sum
			m.GetHistogram().DataPoints = append(m.GetHistogram().DataPoints, &metricspb.HistogramDataPoint{
				Attributes:        kvs(attrs),
				StartTimeUnixNano: uint64(o.started.UnixNano()),
				TimeUnixNano:      uint64(p.at.UnixNano()),
				Count:             h.count,
				Sum:               &sum,
				BucketCounts:      h.counts,
				ExplicitBounds:    h.bounds,
			})
			continue
		}
		dp := &metricspb.NumberDataPoint{
			Attributes:        kvs(attrs),
			StartTimeUnixNano: uint64(o.started.UnixNano()),
			TimeUnixNano:      uint64(p.at.UnixNano()),
			Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: p.value},
		}
		if p.sum {
			m.GetSum().DataPoints = append(m.GetSum().DataPoints, dp)
		} else {
			m.GetGauge().DataPoints = append(m.GetGauge().DataPoints, dp)
		}
	}
	req := &colmetrics.ExportMetricsServiceRequest{}
	for _, rk := range order {
		g := groups[rk]
		if rk == "" && len(g.metrics) == 0 && len(order) > 1 {
			continue
		}
		req.ResourceMetrics = append(req.ResourceMetrics, &metricspb.ResourceMetrics{
			Resource:     o.resourceWith(g.res),
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: g.metrics}},
		})
	}
	return req
}

var severityNumber = map[string]logspb.SeverityNumber{
	"DEBUG": logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG,
	"INFO":  logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
	"WARN":  logspb.SeverityNumber_SEVERITY_NUMBER_WARN,
	"ERROR": logspb.SeverityNumber_SEVERITY_NUMBER_ERROR,
}

// LogsRequest builds the OTLP request for the records, grouped by resource like MetricsRequest.
func (o *OTLP) LogsRequest(recs []logRec) *collogs.ExportLogsServiceRequest {
	type group struct {
		res  map[string]string
		recs []*logspb.LogRecord
	}
	groups := map[string]*group{"": {}}
	order := []string{""}
	for _, r := range recs {
		res, attrs := r.res, r.attrs
		rk := resKey(res)
		g := groups[rk]
		if g == nil {
			g = &group{res: res}
			groups[rk] = g
			order = append(order, rk)
		}
		g.recs = append(g.recs, &logspb.LogRecord{
			TimeUnixNano:   uint64(r.at.UnixNano()),
			SeverityText:   r.severity,
			SeverityNumber: severityNumber[r.severity],
			Body:           &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: r.body}},
			Attributes:     kvs(attrs),
		})
	}
	req := &collogs.ExportLogsServiceRequest{}
	for _, rk := range order {
		g := groups[rk]
		if rk == "" && len(g.recs) == 0 && len(order) > 1 {
			continue
		}
		req.ResourceLogs = append(req.ResourceLogs, &logspb.ResourceLogs{
			Resource:  o.resourceWith(g.res),
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: g.recs}},
		})
	}
	return req
}

func (o *OTLP) post(ctx context.Context, path string, m proto.Message) (retry bool, err error) {
	b, err := proto.Marshal(m)
	if err != nil {
		return false, err
	}
	if o.Tee != nil {
		o.Tee(path, b)
	}
	return o.send(ctx, path, b)
}

func (o *OTLP) send(ctx context.Context, path string, b []byte) (retry bool, err error) {
	if len(b) > maxBodyBytes {
		return false, fmt.Errorf("export batch of %d bytes exceeds %d", len(b), maxBodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Base+path, bytes.NewReader(b))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+o.Token)
	resp, err := o.HTTP.Do(req)
	if err != nil {
		o.stats.failed.Add(1)
		return true, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode < 300:
		o.stats.sent.Add(1)
		o.stats.bytes.Add(int64(len(b)))
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		o.stats.failed.Add(1)
		return true, fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	o.stats.rejected.Add(1)
	return false, fmt.Errorf("%s: status %d (batch dropped)", path, resp.StatusCode)
}

// split groups items into runs whose estimated size stays under limit (a single larger item is
// a run of its own).
func split[T any](items []T, size func(T) int, limit int) [][]T {
	var out [][]T
	start, sum := 0, 0
	for i, it := range items {
		if n := size(it); sum+n > limit && i > start {
			out = append(out, items[start:i])
			start, sum = i, 0
		}
		sum += size(it)
	}
	if start < len(items) {
		out = append(out, items[start:])
	}
	return out
}

// Flush sends what is buffered in requests below the body limit. A retryable failure puts the
// unsent rest back (still bounded); a rejected request drops only its own chunk.
func (o *OTLP) Flush(ctx context.Context) error {
	o.flushMu.Lock()
	defer o.flushMu.Unlock()
	o.mu.Lock()
	pts, logs, dropped := o.points, o.logs, o.dropped
	o.points, o.logs, o.dropped, o.bytes = nil, nil, 0, 0
	o.mu.Unlock()
	if dropped > 0 {
		o.stats.dropped.Add(int64(dropped))
		slog.Warn("export buffer full, oldest samples dropped", "dropped", dropped)
	}
	spans := o.takeSpans()
	var first error
	if o.Buffer != nil {
		if err := o.replay(ctx); err != nil {
			first = err
		}
	}
	note := func(err error) {
		if first == nil {
			first = err
		}
	}
	chunks := split(pts, func(p point) int { return p.size }, chunkBytes)
	for i, c := range chunks {
		retry, err := o.post(ctx, "/v1/metrics", o.MetricsRequest(c))
		if err != nil {
			note(err)
			if retry {
				if !o.spillMetrics(chunks[i:]) {
					o.requeue(slices.Concat(chunks[i:]...), nil)
				}
				break
			}
		}
	}
	if err := o.flushSpans(ctx, spans); err != nil {
		note(err)
	}
	if time.Now().Before(o.logsNext) {
		o.requeue(nil, logs)
		return first
	}
	lchunks := split(logs, func(r logRec) int { return r.size }, chunkBytes)
	for i, c := range lchunks {
		retry, err := o.post(ctx, "/v1/logs", o.LogsRequest(c))
		if err == nil {
			o.logFails, o.logsNext = 0, time.Time{}
			continue
		}
		if !retry {
			note(err)
			continue
		}
		slog.Warn("log export failed", "error", err)
		o.logsNext = time.Now().Add(sink.Backoff(o.logFails, rand.Float64()))
		o.logFails++
		if !o.spillLogs(lchunks[i:]) {
			o.requeue(nil, slices.Concat(lchunks[i:]...))
		}
		break
	}
	return first
}

// spill* write unsent chunks to the disk buffer; false (no buffer or a write error) leaves them
// to the in-memory requeue.
func (o *OTLP) spillMetrics(chunks [][]point) bool {
	return o.spill("/v1/metrics", len(chunks), func(i int) proto.Message { return o.MetricsRequest(chunks[i]) })
}

func (o *OTLP) spillLogs(chunks [][]logRec) bool {
	return o.spill("/v1/logs", len(chunks), func(i int) proto.Message { return o.LogsRequest(chunks[i]) })
}

func (o *OTLP) spill(path string, n int, msg func(int) proto.Message) bool {
	if o.Buffer == nil {
		return false
	}
	for i := 0; i < n; i++ {
		b, err := proto.Marshal(msg(i))
		if err != nil {
			return false
		}
		switch err := o.Buffer.Append(append([]byte(path+"\x00"), b...)); {
		case errors.Is(err, wal.ErrFull):
			slog.Warn("disk buffer full, newest batch dropped (buffer_when_full: drop_newest)")
			o.mu.Lock()
			o.dropped++
			o.mu.Unlock()
		case err != nil:
			return false
		}
	}
	return true
}

// replay sends the spilled batches oldest first; a rejected one is dropped, a retryable failure
// stops the replay and keeps the rest.
func (o *OTLP) replay(ctx context.Context) error {
	return o.Buffer.Replay(func(rec []byte) error {
		path, body, ok := bytes.Cut(rec, []byte{0})
		if !ok {
			return nil
		}
		if retry, err := o.send(ctx, string(path), body); err != nil && retry {
			return err
		}
		return nil
	})
}

func (o *OTLP) requeue(pts []point, logs []logRec) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.points = append(pts, o.points...)
	o.logs = append(logs, o.logs...)
	for _, p := range pts {
		o.bytes += p.size
	}
	for _, r := range logs {
		o.bytes += r.size
	}
	o.trim(true)
}

// Buffered is the estimated bytes waiting to be exported (sink.Delivering).
func (o *OTLP) Buffered() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bytes
}

func (o *OTLP) pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.points) + len(o.logs)
}

// Run flushes every 10 s (or sooner when a lot is buffered) until ctx ends, then once more.
func (o *OTLP) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = o.Flush(fctx)
			cancel()
			return
		case <-t.C:
			if time.Now().Before(o.nextTry) {
				continue
			}
			if time.Since(last) < flushEvery && o.pending() < flushAtLeast {
				continue
			}
			if err := o.Flush(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("export failed", "error", err)
				o.nextTry = time.Now().Add(sink.Backoff(o.fails, rand.Float64()))
				o.fails++
			} else {
				o.fails, o.nextTry = 0, time.Time{}
			}
			last = time.Now()
		}
	}
}
