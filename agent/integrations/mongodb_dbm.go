package integrations

// MongoDB depth (track A2): WiredTiger cache and tickets, oplog window, slow currentOp samples,
// profiler statements by query shape (cumulative per shape, joinable on db.query.hash), explain
// of the slowest shapes (queryPlanner only, values removed) and index and collection usage.
// Nothing here enables the profiler: databases with profiling off just have no statements.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/watchtowerobservability/watchtower-agent/agent/dbm"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	mongoMaxStmts      = 200 // shapes tracked; new shapes past this are counted, not stored
	mongoProfileBatch  = 500 // profiler entries read per database per round
	mongoMaxDatabases  = 20
	mongoMaxCollection = 50 // per database, for index and collection stats
	mongoStatsEvery    = 10 // rounds between index/collection stats passes
	mongoExplainTop    = 3
)

// mongoStmt is one query shape's cumulative work since the agent started.
type mongoStmt struct {
	db, coll, op                    string
	calls, ms, docs, keys, returned float64
}

// mongoDeep is the state kept across rounds.
type mongoDeep struct {
	slowMs  int
	lastTS  map[string]time.Time
	stmts   map[string]*mongoStmt
	dropped float64
	round   int
}

func newMongoDeep(slowMs int) *mongoDeep {
	if slowMs <= 0 {
		slowMs = 1000
	}
	return &mongoDeep{slowMs: slowMs, lastTS: map[string]time.Time{}, stmts: map[string]*mongoStmt{}}
}

// EmitWiredTiger emits storage-engine cache, eviction, ticket and latency figures of serverStatus.
func EmitWiredTiger(out sink.Sink, ss any, now time.Time) {
	for _, m := range []struct {
		name string
		keys []string
	}{
		{"mongodb.wiredtiger.cache.bytes", []string{"wiredTiger", "cache", "bytes currently in the cache"}},
		{"mongodb.wiredtiger.cache.max_bytes", []string{"wiredTiger", "cache", "maximum bytes configured"}},
		{"mongodb.wiredtiger.cache.dirty_bytes", []string{"wiredTiger", "cache", "tracked dirty bytes in the cache"}},
		// Tickets: <= 6.x under wiredTiger.concurrentTransactions, 7.0+ under queues.execution.
		{"mongodb.wiredtiger.tickets.read.available", []string{"wiredTiger", "concurrentTransactions", "read", "available"}},
		{"mongodb.wiredtiger.tickets.write.available", []string{"wiredTiger", "concurrentTransactions", "write", "available"}},
		{"mongodb.wiredtiger.tickets.read.available", []string{"queues", "execution", "read", "available"}},
		{"mongodb.wiredtiger.tickets.write.available", []string{"queues", "execution", "write", "available"}},
		{"mongodb.global_lock.queue", []string{"globalLock", "currentQueue", "total"}},
	} {
		if v, ok := num(ss, m.keys...); ok {
			out.Gauge(m.name, "1", v, nil, now)
		}
	}
	for _, m := range []struct {
		name string
		keys []string
	}{
		{"mongodb.wiredtiger.cache.pages_read", []string{"wiredTiger", "cache", "pages read into cache"}},
		{"mongodb.wiredtiger.cache.pages_written", []string{"wiredTiger", "cache", "pages written from cache"}},
		{"mongodb.wiredtiger.cache.app_evictions", []string{"wiredTiger", "cache", "pages evicted by application threads"}},
		{"mongodb.wiredtiger.cache.modified_evicted", []string{"wiredTiger", "cache", "modified pages evicted"}},
	} {
		if v, ok := num(ss, m.keys...); ok {
			out.Sum(m.name, "{pages}", v, nil, now)
		}
	}
	for _, k := range []string{"reads", "writes", "commands"} {
		a := map[string]string{"db.operation.name": k}
		if v, ok := num(ss, "opLatencies", k, "latency"); ok {
			out.Sum("mongodb.latency.total", "us", v, a, now)
		}
		if v, ok := num(ss, "opLatencies", k, "ops"); ok {
			out.Sum("mongodb.latency.ops", "{operations}", v, a, now)
		}
	}
}

// OplogWindow is the time the oplog covers, from its first and last entries.
func OplogWindow(first, last bson.Timestamp) float64 {
	if last.T < first.T {
		return 0
	}
	return float64(last.T - first.T)
}

// toJSON converts a BSON document to plain JSON values (relaxed extended JSON).
func toJSON(d any) any {
	b, err := bson.MarshalExtJSON(d, false, false)
	if err != nil {
		return nil
	}
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

// mongoNoise is driver and session bookkeeping that is not part of a query's shape.
var mongoNoise = []string{"lsid", "$clusterTime", "$db", "$readPreference", "txnNumber", "autocommit",
	"startTransaction", "readConcern", "writeConcern", "comment", "maxTimeMS", "$audit", "$client", "cursor", "shardVersion"}

// mongoShape is the value-free shape of a command and its hash.
func mongoShape(cmd any) (string, string) {
	v, _ := toJSON(cmd).(map[string]any)
	for _, k := range mongoNoise {
		delete(v, k)
	}
	s := dbm.ShapeText(v)
	return s, dbm.Hash(s)
}

func str(d any, key string) string {
	v, _ := get(d, key)
	s, _ := v.(string)
	return s
}

// splitNS turns `db.coll` into its parts; for `db.$cmd` the collection is the command's target.
func splitNS(ns string, cmd any) (string, string) {
	db, coll, _ := strings.Cut(ns, ".")
	if coll == "$cmd" {
		coll = ""
		if d, ok := cmd.(bson.D); ok && len(d) > 0 {
			coll, _ = d[0].Value.(string)
		}
	}
	return db, coll
}

// profEntry is what a system.profile document tells about one operation.
type profEntry struct {
	db, coll, op, shape, hash, plan string
	ms, docs, keys, returned        float64
	cmd                             bson.D
	ts                              time.Time
}

func parseProfile(d bson.D) profEntry {
	cmd, _ := mustGet(d, "command").(bson.D)
	e := profEntry{op: str(d, "op"), plan: str(d, "planSummary"), cmd: cmd}
	e.db, e.coll = splitNS(str(d, "ns"), cmd)
	e.shape, e.hash = mongoShape(cmd)
	e.ms, _ = num(d, "millis")
	e.docs, _ = num(d, "docsExamined")
	e.keys, _ = num(d, "keysExamined")
	e.returned, _ = num(d, "nreturned")
	if t, ok := mustGet(d, "ts").(bson.DateTime); ok {
		e.ts = t.Time()
	}
	return e
}

func mustGet(d any, k string) any {
	v, _ := get(d, k)
	return v
}

// AddProfile folds one database's new profiler entries into the per-shape totals, emits a sample
// for each slow one and returns the slow entries, slowest first (explain candidates).
func (m *mongoDeep) AddProfile(out sink.Sink, docs []bson.D, now time.Time) []profEntry {
	var slow []profEntry
	for _, d := range docs {
		e := parseProfile(d)
		if e.ts.After(m.lastTS[e.db]) {
			m.lastTS[e.db] = e.ts
		}
		s := m.stmts[e.hash]
		if s == nil {
			if len(m.stmts) >= mongoMaxStmts {
				m.dropped++
				continue
			}
			s = &mongoStmt{db: e.db, coll: e.coll, op: e.op}
			m.stmts[e.hash] = s
		}
		s.calls++
		s.ms += e.ms
		s.docs += e.docs
		s.keys += e.keys
		s.returned += e.returned
		if e.ms >= float64(m.slowMs) {
			slow = append(slow, e)
		}
	}
	sort.Slice(slow, func(i, j int) bool { return slow[i].ms > slow[j].ms })
	for _, e := range slow[:min(len(slow), 10)] {
		dbm.EmitSample(out, "mongodb", "query.sample", "INFO", map[string]any{"op": e.op, "shape": e.shape, "ms": e.ms,
			"docs_examined": e.docs, "keys_examined": e.keys, "returned": e.returned, "plan": e.plan},
			map[string]string{"db.namespace": e.db, "db.collection.name": e.coll, "db.query.hash": e.hash}, now)
	}
	return slow
}

// EmitStatements writes every tracked shape's cumulative totals.
func (m *mongoDeep) EmitStatements(out sink.Sink, now time.Time) {
	for h, s := range m.stmts {
		a := map[string]string{"db.query.hash": h, "db.namespace": s.db, "db.collection.name": s.coll,
			"db.operation.name": s.op, "db.query.summary": strings.TrimSpace(s.op + " " + s.coll)}
		out.Sum("mongodb.statement.calls", "{calls}", s.calls, a, now)
		out.Sum("mongodb.statement.total_time", "ms", s.ms, a, now)
		out.Sum("mongodb.statement.docs_examined", "{documents}", s.docs, a, now)
		out.Sum("mongodb.statement.keys_examined", "{keys}", s.keys, a, now)
		out.Sum("mongodb.statement.returned", "{documents}", s.returned, a, now)
	}
	out.Sum("mongodb.statement.dropped", "{shapes}", m.dropped, nil, now)
}

// EmitCurrentOp reports in-progress operations already running past the slow threshold.
func EmitCurrentOp(out sink.Sink, ops []bson.D, now time.Time) {
	waiting := 0.0
	for _, d := range ops[:min(len(ops), 20)] {
		cmd, _ := mustGet(d, "command").(bson.D)
		db, coll := splitNS(str(d, "ns"), cmd)
		shape, hash := mongoShape(cmd)
		us, _ := num(d, "microsecs_running")
		lock, _ := mustGet(d, "waitingForLock").(bool)
		if lock {
			waiting++
		}
		dbm.EmitSample(out, "mongodb", "query.sample", "WARN", map[string]any{"op": str(d, "op"), "shape": shape,
			"running_ms": us / 1000, "waiting_for_lock": lock, "plan": str(d, "planSummary"), "state": "running"},
			map[string]string{"db.namespace": db, "db.collection.name": coll, "db.query.hash": hash}, now)
	}
	out.Gauge("mongodb.operations.slow_active", "{operations}", float64(len(ops)), nil, now)
	out.Gauge("mongodb.operations.waiting_for_lock", "{operations}", waiting, nil, now)
}

// planValues is where an explain plan carries values; those subtrees are shaped, the rest kept.
var planValues = map[string]bool{"filter": true, "indexBounds": true, "parsedQuery": true}

// RedactPlan keeps stages, index names and key patterns of a plan and shapes every value-bearing part.
func RedactPlan(v any) (any, bool) {
	collscan := false
	var walk func(any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			m := make(map[string]any, len(t))
			for k, x := range t {
				if planValues[k] {
					m[k] = dbm.Shape(x)
					continue
				}
				if k == "stage" && x == "COLLSCAN" {
					collscan = true
				}
				m[k] = walk(x)
			}
			return m
		case []any:
			out := make([]any, len(t))
			for i, x := range t {
				out[i] = walk(x)
			}
			return out
		}
		return v
	}
	return walk(v), collscan
}

// EmitMongoPlan writes the redacted winning plan of an explain reply.
func EmitMongoPlan(out sink.Sink, e profEntry, reply bson.D, now time.Time) {
	wp, ok := dig(toJSON(reply), "queryPlanner", "winningPlan")
	if !ok {
		return
	}
	plan, collscan := RedactPlan(wp)
	a := map[string]string{"db.namespace": e.db, "db.collection.name": e.coll, "db.query.hash": e.hash}
	if collscan {
		a["db.plan.collscan"] = "true"
	}
	dbm.EmitSample(out, "mongodb", "query.plan", "INFO", map[string]any{"shape": e.shape, "winning_plan": plan}, a, now)
}

// mongoExplainable strips the bookkeeping from a read command so it can be explained as is.
func mongoExplainable(e profEntry) bson.D {
	if len(e.cmd) == 0 {
		return nil
	}
	switch e.cmd[0].Key {
	case "find", "aggregate", "count", "distinct":
	default:
		return nil
	}
	var c bson.D
	for _, kv := range e.cmd {
		if !strings.HasPrefix(kv.Key, "$") && kv.Key != "lsid" && kv.Key != "txnNumber" {
			c = append(c, kv)
		}
	}
	return c
}

// EmitIndexStats writes $indexStats accesses (cumulative since the index was loaded).
func EmitIndexStats(out sink.Sink, db, coll string, rows []bson.D, now time.Time) {
	for _, r := range rows {
		v, _ := num(r, "accesses", "ops")
		out.Sum("mongodb.index.accesses", "{operations}", v, map[string]string{"db.namespace": db,
			"db.collection.name": coll, "mongodb.index.name": str(r, "name")}, now)
	}
}

// EmitCollStats writes $collStats storage figures.
func EmitCollStats(out sink.Sink, db, coll string, rows []bson.D, now time.Time) {
	a := map[string]string{"db.namespace": db, "db.collection.name": coll}
	for _, r := range rows[:min(len(rows), 1)] {
		for k, n := range map[string]string{"size": "mongodb.collection.size", "storageSize": "mongodb.collection.storage_size",
			"totalIndexSize": "mongodb.collection.index_size"} {
			if v, ok := num(r, "storageStats", k); ok {
				out.Gauge(n, "By", v, a, now)
			}
		}
		if v, ok := num(r, "storageStats", "count"); ok {
			out.Gauge("mongodb.collection.documents", "{documents}", v, a, now)
		}
	}
}

func aggregate(ctx context.Context, db *mongo.Database, coll string, pipe bson.A) []bson.D {
	var cur *mongo.Cursor
	var err error
	if coll == "" {
		cur, err = db.Aggregate(ctx, pipe)
	} else {
		cur, err = db.Collection(coll).Aggregate(ctx, pipe)
	}
	if err != nil {
		return nil
	}
	var rows []bson.D
	_ = cur.All(ctx, &rows)
	return rows
}

// collect runs one round of the deeper reads. Each part is best effort: a missing privilege
// (clusterMonitor covers currentOp; read on each database covers the profiler) skips that part.
func (m *mongoDeep) collect(ctx context.Context, cl *mongo.Client, out sink.Sink, dbs []string, replica bool, now time.Time) {
	m.round++
	admin := cl.Database("admin")
	ops := aggregate(ctx, admin, "", bson.A{
		bson.D{{Key: "$currentOp", Value: bson.D{{Key: "allUsers", Value: true}}}},
		bson.D{{Key: "$match", Value: bson.D{{Key: "active", Value: true},
			{Key: "microsecs_running", Value: bson.D{{Key: "$gte", Value: int64(m.slowMs) * 1000}}}}}},
		bson.D{{Key: "$limit", Value: 50}}})
	EmitCurrentOp(out, ops, now)
	if replica {
		oplog := cl.Database("local").Collection("oplog.rs")
		var first, last struct {
			TS bson.Timestamp `bson:"ts"`
		}
		end := func(dir int) *options.FindOneOptionsBuilder {
			return options.FindOne().SetProjection(bson.D{{Key: "ts", Value: 1}}).SetSort(bson.D{{Key: "$natural", Value: dir}})
		}
		if oplog.FindOne(ctx, bson.D{}, end(1)).Decode(&first) == nil && oplog.FindOne(ctx, bson.D{}, end(-1)).Decode(&last) == nil {
			out.Gauge("mongodb.oplog.window", "s", OplogWindow(first.TS, last.TS), nil, now)
		}
	}
	var slow []profEntry
	for _, name := range dbs {
		since := m.lastTS[name]
		if since.IsZero() {
			since = now.Add(-time.Minute)
		}
		cur, err := cl.Database(name).Collection("system.profile").Find(ctx, bson.D{{Key: "ts", Value: bson.D{{Key: "$gt", Value: since}}}},
			options.Find().SetSort(bson.D{{Key: "ts", Value: 1}}).SetLimit(mongoProfileBatch))
		if err != nil {
			continue
		}
		var docs []bson.D
		if cur.All(ctx, &docs) == nil {
			slow = append(slow, m.AddProfile(out, docs, now)...)
		}
	}
	m.EmitStatements(out, now)
	sort.Slice(slow, func(i, j int) bool { return slow[i].ms > slow[j].ms })
	seen := map[string]bool{}
	for _, e := range slow {
		c := mongoExplainable(e)
		if c == nil || seen[e.hash] || len(seen) >= mongoExplainTop {
			continue
		}
		seen[e.hash] = true
		var reply bson.D
		if cl.Database(e.db).RunCommand(ctx, bson.D{{Key: "explain", Value: c}, {Key: "verbosity", Value: "queryPlanner"}}).Decode(&reply) == nil {
			EmitMongoPlan(out, e, reply, now)
		}
	}
	if m.round%mongoStatsEvery != 1 {
		return
	}
	for _, name := range dbs {
		db := cl.Database(name)
		colls, err := db.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
		if err != nil {
			continue
		}
		sort.Strings(colls)
		for _, coll := range colls[:min(len(colls), mongoMaxCollection)] {
			if strings.HasPrefix(coll, "system.") {
				continue
			}
			EmitIndexStats(out, name, coll, aggregate(ctx, db, coll, bson.A{bson.D{{Key: "$indexStats", Value: bson.D{}}}}), now)
			EmitCollStats(out, name, coll, aggregate(ctx, db, coll, bson.A{bson.D{{Key: "$collStats",
				Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}}), now)
		}
	}
}

// mongoDatabases is the configured list, or every non-system database (at most 20).
func mongoDatabases(ctx context.Context, cl *mongo.Client, conf []string) []string {
	if len(conf) > 0 {
		return conf
	}
	names, err := cl.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		if n != "admin" && n != "local" && n != "config" && len(out) < mongoMaxDatabases {
			out = append(out, n)
		}
	}
	return out
}
