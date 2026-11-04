package integrations

// Elasticsearch and OpenSearch depth (track A2): per-node search, indexing, merge and refresh
// latency, thread pool queues and rejections, JVM heap and GC, circuit breaker trips, shard
// states with the allocation explanation of an unassigned shard, long-running search and bulk
// tasks (index names and timings, never the query source) and hot threads when a node is busy.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	esHotEvery  = 10 // rounds between hot thread captures (5 min at 30 s)
	esHotCPU    = 50 // percent of one thread's CPU that makes hot threads worth filing
	esSlowTask  = time.Second
	esMaxShards = 2000
)

type esDeep struct {
	system string // elasticsearch or opensearch, read once
	round  int
}

func (d *esDeep) collect(ctx context.Context, c HTTPConfig, hdr map[string]string, out sink.Sink, now time.Time) {
	d.round++
	get := func(path string, v any) error { return doJSON(ctx, c, http.MethodGet, c.URL+path, hdr, nil, v) }
	if d.system == "" {
		var root struct {
			Version struct {
				Distribution string `json:"distribution"`
			} `json:"version"`
		}
		d.system = "elasticsearch"
		if get("/", &root) == nil && root.Version.Distribution == "opensearch" {
			d.system = "opensearch"
		}
	}
	var ns esNodeStats
	if get("/_nodes/stats/indices,thread_pool,jvm,breaker", &ns) == nil {
		EmitESNodes(out, ns, now)
	}
	var shards []map[string]string
	if get("/_cat/shards?format=json&h=index,shard,prirep,state,unassigned.reason", &shards) == nil {
		if EmitESShards(out, shards, now) > 0 {
			var ex map[string]any
			// No body: the cluster explains the first unassigned shard it finds.
			if doJSON(ctx, c, http.MethodPost, c.URL+"/_cluster/allocation/explain", hdr, nil, &ex) == nil {
				EmitESAllocation(out, d.system, ex, now)
			}
		}
	}
	var tasks esTasks
	if get("/_tasks?detailed=true&actions=*search*,*bulk*,*reindex*,*by_query*", &tasks) == nil {
		EmitESTasks(out, d.system, tasks, now)
	}
	if d.round%esHotEvery == 1 {
		if b, err := getBodyHdr(ctx, c, c.URL+"/_nodes/hot_threads?threads=3&interval=500ms", hdr); err == nil {
			EmitESHotThreads(out, d.system, string(b), now)
		}
	}
}

// getBodyHdr is getBody with extra headers (the API key); hot_threads replies in plain text.
func getBodyHdr(ctx context.Context, c HTTPConfig, url string, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

type esNodeStats struct {
	Nodes map[string]struct {
		Name    string `json:"name"`
		Indices struct {
			Search struct {
				QueryTotal  float64 `json:"query_total"`
				QueryMs     float64 `json:"query_time_in_millis"`
				FetchTotal  float64 `json:"fetch_total"`
				FetchMs     float64 `json:"fetch_time_in_millis"`
				OpenContext float64 `json:"open_contexts"`
			} `json:"search"`
			Indexing struct {
				Total float64 `json:"index_total"`
				Ms    float64 `json:"index_time_in_millis"`
			} `json:"indexing"`
			Merges struct {
				Total float64 `json:"total"`
				Ms    float64 `json:"total_time_in_millis"`
			} `json:"merges"`
			Refresh struct {
				Total float64 `json:"total"`
				Ms    float64 `json:"total_time_in_millis"`
			} `json:"refresh"`
		} `json:"indices"`
		ThreadPool map[string]struct {
			Queue    float64 `json:"queue"`
			Active   float64 `json:"active"`
			Rejected float64 `json:"rejected"`
		} `json:"thread_pool"`
		JVM struct {
			Mem struct {
				HeapPercent float64 `json:"heap_used_percent"`
			} `json:"mem"`
			GC struct {
				Collectors map[string]struct {
					Count float64 `json:"collection_count"`
					Ms    float64 `json:"collection_time_in_millis"`
				} `json:"collectors"`
			} `json:"gc"`
		} `json:"jvm"`
		Breakers map[string]struct {
			Tripped float64 `json:"tripped"`
		} `json:"breakers"`
	} `json:"nodes"`
}

// esPools are the thread pools whose queues and rejections matter (others are internal).
var esPools = map[string]bool{"search": true, "write": true, "get": true, "management": true, "refresh": true,
	"flush": true, "force_merge": true, "snapshot": true, "analyze": true, "search_throttled": true}

// EmitESNodes writes per-node latency totals, thread pools, heap, GC and breakers.
func EmitESNodes(out sink.Sink, ns esNodeStats, now time.Time) {
	for _, n := range ns.Nodes {
		a := map[string]string{"elasticsearch.node.name": n.Name}
		ix := n.Indices
		for _, m := range []struct {
			name, unit string
			v          float64
		}{
			{"elasticsearch.node.search.queries", "{queries}", ix.Search.QueryTotal},
			{"elasticsearch.node.search.query_time", "ms", ix.Search.QueryMs},
			{"elasticsearch.node.search.fetches", "{fetches}", ix.Search.FetchTotal},
			{"elasticsearch.node.search.fetch_time", "ms", ix.Search.FetchMs},
			{"elasticsearch.node.indexing.docs", "{documents}", ix.Indexing.Total},
			{"elasticsearch.node.indexing.time", "ms", ix.Indexing.Ms},
			{"elasticsearch.node.merges", "{merges}", ix.Merges.Total},
			{"elasticsearch.node.merges.time", "ms", ix.Merges.Ms},
			{"elasticsearch.node.refreshes", "{refreshes}", ix.Refresh.Total},
			{"elasticsearch.node.refresh.time", "ms", ix.Refresh.Ms},
		} {
			out.Sum(m.name, m.unit, m.v, a, now)
		}
		out.Gauge("elasticsearch.node.search.open_contexts", "{contexts}", ix.Search.OpenContext, a, now)
		out.Gauge("elasticsearch.node.jvm.heap_used_percent", "%", n.JVM.Mem.HeapPercent, a, now)
		for name, p := range n.ThreadPool {
			if !esPools[name] {
				continue
			}
			pa := sink.With(a, "thread_pool", name)
			out.Gauge("elasticsearch.node.thread_pool.queue", "{tasks}", p.Queue, pa, now)
			out.Gauge("elasticsearch.node.thread_pool.active", "{threads}", p.Active, pa, now)
			out.Sum("elasticsearch.node.thread_pool.rejected", "{tasks}", p.Rejected, pa, now)
		}
		for name, g := range n.JVM.GC.Collectors {
			ga := sink.With(a, "gc", name)
			out.Sum("elasticsearch.node.jvm.gc.collections", "{collections}", g.Count, ga, now)
			out.Sum("elasticsearch.node.jvm.gc.time", "ms", g.Ms, ga, now)
		}
		for name, b := range n.Breakers {
			out.Sum("elasticsearch.node.breaker.tripped", "{trips}", b.Tripped, sink.With(a, "breaker", name), now)
		}
	}
}

// EmitESShards counts shards by state and primary/replica, and unassigned shards by reason. It
// returns the unassigned count.
func EmitESShards(out sink.Sink, shards []map[string]string, now time.Time) int {
	by := map[[2]string]float64{}
	reasons := map[string]float64{}
	unassigned := 0
	for _, s := range shards[:min(len(shards), esMaxShards)] {
		role := "replica"
		if s["prirep"] == "p" {
			role = "primary"
		}
		by[[2]string{s["state"], role}]++
		if s["state"] == "UNASSIGNED" {
			unassigned++
			reasons[s["unassigned.reason"]]++
		}
	}
	for _, st := range []string{"STARTED", "INITIALIZING", "RELOCATING", "UNASSIGNED"} {
		for _, role := range []string{"primary", "replica"} {
			out.Gauge("elasticsearch.shards", "{shards}", by[[2]string{st, role}],
				map[string]string{"state": strings.ToLower(st), "role": role}, now)
		}
	}
	for r, n := range reasons {
		out.Gauge("elasticsearch.shards.unassigned", "{shards}", n, map[string]string{"reason": r}, now)
	}
	return unassigned
}

// EmitESAllocation files the allocation explanation of the first unassigned shard: the index,
// shard, why it is unassigned and each node's deciding reason (deduplicated).
func EmitESAllocation(out sink.Sink, sys string, ex map[string]any, now time.Time) {
	why := map[string]bool{}
	nodes, _ := ex["node_allocation_decisions"].([]any)
	for _, n := range nodes {
		nm, _ := n.(map[string]any)
		ds, _ := nm["deciders"].([]any)
		for _, d := range ds {
			m, _ := d.(map[string]any)
			if e, ok := m["explanation"].(string); ok {
				why[sink.Truncate(e, 300)] = true
			}
		}
	}
	reasons := make([]string, 0, len(why))
	for r := range why {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	info, _ := ex["unassigned_info"].(map[string]any)
	dbm.EmitSample(out, sys, "shard", "WARN", map[string]any{"index": ex["index"], "shard": ex["shard"], "primary": ex["primary"],
		"can_allocate": ex["can_allocate"], "explanation": ex["allocate_explanation"], "unassigned_reason": info["reason"],
		"deciders": reasons[:min(len(reasons), 10)]}, map[string]string{"db.namespace": anyStr(ex["index"])}, now)
}

func anyStr(v any) string { s, _ := v.(string); return s }

type esTasks struct {
	Nodes map[string]struct {
		Name  string `json:"name"`
		Tasks map[string]struct {
			Action      string  `json:"action"`
			Description string  `json:"description"`
			RunningNs   float64 `json:"running_time_in_nanos"`
			Cancellable bool    `json:"cancellable"`
			ParentTask  string  `json:"parent_task_id"`
		} `json:"tasks"`
	} `json:"nodes"`
}

var esIndicesRE = regexp.MustCompile(`indices\[([^\]]*)\]`)

// EmitESTasks reports top-level tasks running past esSlowTask: a gauge per action and a sample
// each (at most 20) with the indices and running time. The description's query source is dropped.
func EmitESTasks(out sink.Sink, sys string, t esTasks, now time.Time) {
	count := map[string]float64{}
	sampled, total := 0, 0
	for _, n := range t.Nodes {
		for _, task := range n.Tasks {
			if task.ParentTask != "" || task.RunningNs < float64(esSlowTask) {
				continue // child tasks repeat their parent
			}
			count[task.Action]++
			total++
			if sampled >= 20 {
				continue
			}
			sampled++
			idx := ""
			if m := esIndicesRE.FindStringSubmatch(task.Description); m != nil {
				idx = sink.Truncate(m[1], 300)
			}
			dbm.EmitSample(out, sys, "query.sample", "WARN", map[string]any{"action": task.Action, "indices": idx,
				"running_ms": task.RunningNs / 1e6, "node": n.Name, "cancellable": task.Cancellable, "state": "running"},
				map[string]string{"db.operation.name": task.Action, "db.namespace": idx}, now)
		}
	}
	out.Gauge("elasticsearch.tasks.slow", "{tasks}", float64(total), nil, now)
	for a, c := range count {
		out.Gauge("elasticsearch.tasks.slow.by_action", "{tasks}", c, map[string]string{"db.operation.name": a}, now)
	}
}

var esHotRE = regexp.MustCompile(`(?m)^\s*([0-9.]+)% \[cpu=`)

// EmitESHotThreads emits the busiest thread's CPU share and files the report when it is past esHotCPU.
func EmitESHotThreads(out sink.Sink, sys, report string, now time.Time) {
	peak := 0.0
	for _, m := range esHotRE.FindAllStringSubmatch(report, -1) {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			peak = max(peak, f)
		}
	}
	out.Gauge("elasticsearch.hot_threads.peak_cpu", "%", peak, nil, now)
	if peak >= esHotCPU {
		dbm.EmitSample(out, sys, "wait", "WARN", map[string]any{"source": "hot_threads", "peak_cpu": peak,
			"report": sink.Truncate(report, 6000)}, nil, now)
	}
}
