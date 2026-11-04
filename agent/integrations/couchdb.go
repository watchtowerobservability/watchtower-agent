package integrations

// CouchDB (track A2): node statistics (request time percentiles, reads/writes, open
// databases and files, HTTP methods and status codes), active tasks (compaction, indexing,
// replication) with their age, replication scheduler states and, every 10th round, per-database
// file vs active size (compaction need) and document counts. Replication endpoints are never
// reported: their URLs can carry credentials.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	couchMaxSeries = 2000
	couchMaxDBs    = 100
	couchDBEvery   = 10
)

// CouchDB polls a node every 30 s (url http://host:5984, an admin or a user with _node read).
func CouchDB(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	round := 0
	return Loop(ctx, "couchdb", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		round++
		get := func(p string, v any) error { return doJSON(ctx, *c, http.MethodGet, c.URL+p, nil, nil, v) }
		var stats map[string]any
		if err := get("/_node/_local/_stats", &stats); err != nil {
			return err
		}
		if EmitCouchStats(out, stats, now) == 0 {
			return errors.New("couchdb: _stats has no metrics")
		}
		var tasks []map[string]any
		if get("/_active_tasks", &tasks) == nil {
			EmitCouchTasks(out, tasks, now)
		}
		var docs struct {
			Docs []map[string]any `json:"docs"`
		}
		if get("/_scheduler/docs?limit=1000", &docs) == nil {
			EmitCouchReplications(out, docs.Docs, now)
		}
		if round%couchDBEvery != 1 {
			return nil
		}
		var dbs []string
		if get("/_all_dbs?limit="+strconv.Itoa(couchMaxDBs), &dbs) != nil {
			return nil
		}
		for _, db := range dbs {
			var info map[string]any
			if get("/"+url.PathEscape(db), &info) == nil {
				EmitCouchDB(out, db, info, now)
			}
		}
		return nil
	})
}

// couchLabelled is a leaf whose key is a label value (an HTTP status or method), not a name.
func couchLabelled(k string) bool {
	return k != "" && (strings.Trim(k, "0123456789") == "" || strings.ToUpper(k) == k)
}

// EmitCouchStats walks _stats: every {value, type} leaf becomes couchdb.<path>; counters are
// sums, gauges gauges, histograms emit their mean and p50/p90/p99. It returns the series count.
func EmitCouchStats(out sink.Sink, stats map[string]any, now time.Time) int {
	n := 0
	var walk func(path []string, v map[string]any)
	walk = func(path []string, v map[string]any) {
		if typ, ok := v["type"].(string); ok {
			if n >= couchMaxSeries {
				return
			}
			name, a := "couchdb."+strings.Join(path, "."), map[string]string(nil)
			if last := path[len(path)-1]; len(path) > 1 && couchLabelled(last) {
				name, a = "couchdb."+strings.Join(path[:len(path)-1], "."), map[string]string{"key": last}
			}
			switch typ {
			case "counter":
				if f, ok := v["value"].(float64); ok {
					out.Sum(name, "1", f, a, now)
					n++
				}
			case "gauge":
				if f, ok := v["value"].(float64); ok {
					out.Gauge(name, "1", f, a, now)
					n++
				}
			case "histogram":
				h, _ := v["value"].(map[string]any)
				if f, ok := h["arithmetic_mean"].(float64); ok {
					out.Gauge(name+".mean", "1", f, a, now)
					n++
				}
				ps, _ := h["percentile"].([]any)
				for _, p := range ps {
					pair, _ := p.([]any)
					if len(pair) != 2 {
						continue
					}
					q, _ := pair[0].(float64)
					f, ok := pair[1].(float64)
					if ok && (q == 50 || q == 90 || q == 99) {
						out.Gauge(name, "1", f, sink.With(a, "quantile", strconv.Itoa(int(q))), now)
						n++
					}
				}
			}
			return
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if m, ok := v[k].(map[string]any); ok {
				walk(append(append([]string(nil), path...), k), m)
			}
		}
	}
	walk(nil, stats)
	return n
}

// EmitCouchTasks counts active tasks by type with the oldest one's age and mean progress.
func EmitCouchTasks(out sink.Sink, tasks []map[string]any, now time.Time) {
	type agg struct{ n, oldest, progress float64 }
	by := map[string]*agg{}
	for _, t := range tasks {
		typ, _ := t["type"].(string)
		a := by[typ]
		if a == nil {
			a = &agg{}
			by[typ] = a
		}
		a.n++
		if s, ok := t["started_on"].(float64); ok {
			a.oldest = max(a.oldest, float64(now.Unix())-s)
		}
		p, _ := t["progress"].(float64)
		a.progress += p
	}
	for typ, a := range by {
		l := map[string]string{"task_type": typ}
		out.Gauge("couchdb.active_tasks", "{tasks}", a.n, l, now)
		out.Gauge("couchdb.active_tasks.oldest_age", "s", a.oldest, l, now)
		out.Gauge("couchdb.active_tasks.progress", "%", a.progress/a.n, l, now)
	}
}

// EmitCouchReplications counts scheduler replication documents by state.
func EmitCouchReplications(out sink.Sink, docs []map[string]any, now time.Time) {
	by := map[string]float64{"running": 0, "pending": 0, "crashing": 0, "failed": 0, "completed": 0}
	for _, d := range docs {
		if s, ok := d["state"].(string); ok {
			by[s]++
		}
	}
	for s, n := range by {
		out.Gauge("couchdb.replications", "{replications}", n, map[string]string{"state": s}, now)
	}
}

// EmitCouchDB emits one database's sizes, document counts and the share compaction would free.
func EmitCouchDB(out sink.Sink, db string, info map[string]any, now time.Time) {
	a := map[string]string{"db.namespace": db}
	sizes, _ := info["sizes"].(map[string]any)
	file, _ := sizes["file"].(float64)
	active, _ := sizes["active"].(float64)
	out.Gauge("couchdb.database.file_size", "By", file, a, now)
	out.Gauge("couchdb.database.active_size", "By", active, a, now)
	if file > 0 {
		out.Gauge("couchdb.database.fragmentation", "1", max(1-active/file, 0), a, now)
	}
	docs, _ := info["doc_count"].(float64)
	del, _ := info["doc_del_count"].(float64)
	out.Gauge("couchdb.database.documents", "{documents}", docs, a, now)
	out.Gauge("couchdb.database.deleted_documents", "{documents}", del, a, now)
}
