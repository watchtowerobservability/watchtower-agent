package integrations

import (
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// profileDoc is a system.profile entry as MongoDB 7 records a find.
func profileDoc(status string, total int32, ms int32, at time.Time) bson.D {
	return bson.D{
		{Key: "op", Value: "query"}, {Key: "ns", Value: "shop.orders"},
		{Key: "command", Value: bson.D{{Key: "find", Value: "orders"},
			{Key: "filter", Value: bson.D{{Key: "status", Value: status}, {Key: "total", Value: bson.D{{Key: "$gt", Value: total}}}}},
			{Key: "lsid", Value: bson.D{{Key: "id", Value: "x"}}}, {Key: "$db", Value: "shop"}}},
		{Key: "keysExamined", Value: int32(0)}, {Key: "docsExamined", Value: int32(5000)}, {Key: "nreturned", Value: int32(3)},
		{Key: "millis", Value: ms}, {Key: "planSummary", Value: "COLLSCAN"}, {Key: "ts", Value: bson.NewDateTimeFromTime(at)},
	}
}

func TestMongoProfilerGroupsByShapeWithoutValues(t *testing.T) {
	now := time.Now()
	m := newMongoDeep(100)
	rec := &sink.Recorder{}
	slow := m.AddProfile(rec, []bson.D{profileDoc("paid", 100, 250, now), profileDoc("new", 7, 20, now.Add(time.Millisecond))}, now)
	m.EmitStatements(rec, now)
	if len(m.stmts) != 1 || len(slow) != 1 || slow[0].ms != 250 {
		t.Fatalf("stmts %d slow %+v", len(m.stmts), slow)
	}
	if !m.lastTS["shop"].Equal(now.Add(time.Millisecond).Truncate(time.Millisecond)) {
		t.Fatalf("lastTS %v", m.lastTS["shop"])
	}
	var calls, docs float64
	for _, s := range rec.Samples {
		if s.Name == "" && (strings.Contains(s.Body, "paid") || strings.Contains(s.Body, `"$gt":100`)) {
			t.Fatalf("value leaked: %s", s.Body)
		}
		switch s.Name {
		case "mongodb.statement.calls":
			calls = s.Value
			if s.Attrs["db.collection.name"] != "orders" || s.Attrs["db.query.hash"] == "" {
				t.Fatalf("%+v", s.Attrs)
			}
		case "mongodb.statement.docs_examined":
			docs = s.Value
		}
	}
	if calls != 2 || docs != 10000 {
		t.Fatalf("calls %v docs %v", calls, docs)
	}
	if !strings.Contains(slow[0].shape, `"filter":{"status":"?","total":{"$gt":"?"}}`) || strings.Contains(slow[0].shape, "lsid") {
		t.Fatal(slow[0].shape)
	}
}

func TestMongoExplainPlanIsRedacted(t *testing.T) {
	e := parseProfile(profileDoc("paid", 100, 250, time.Now()))
	if c := mongoExplainable(e); len(c) != 2 || c[0].Key != "find" {
		t.Fatalf("explain command %v", c)
	}
	reply := bson.D{{Key: "queryPlanner", Value: bson.D{{Key: "winningPlan", Value: bson.D{
		{Key: "stage", Value: "COLLSCAN"}, {Key: "direction", Value: "forward"},
		{Key: "filter", Value: bson.D{{Key: "status", Value: bson.D{{Key: "$eq", Value: "paid"}}}}}}}}}}
	rec := &sink.Recorder{}
	EmitMongoPlan(rec, e, reply, time.Now())
	s := rec.Samples[0]
	if s.Attrs["db.plan.collscan"] != "true" || s.Attrs["event.name"] != "db.query.plan" || strings.Contains(s.Body, "paid") ||
		!strings.Contains(s.Body, `"stage":"COLLSCAN"`) {
		t.Fatalf("%+v", s)
	}
}

func TestMongoWiredTigerOplogAndCurrentOp(t *testing.T) {
	ss := bson.D{{Key: "wiredTiger", Value: bson.D{{Key: "cache", Value: bson.D{
		{Key: "bytes currently in the cache", Value: int64(800)}, {Key: "maximum bytes configured", Value: int64(1000)},
		{Key: "pages evicted by application threads", Value: int64(4)}}}}},
		{Key: "queues", Value: bson.D{{Key: "execution", Value: bson.D{{Key: "write", Value: bson.D{{Key: "available", Value: int32(2)}}}}}}},
		{Key: "opLatencies", Value: bson.D{{Key: "reads", Value: bson.D{{Key: "latency", Value: int64(9000)}, {Key: "ops", Value: int64(3)}}}}}}
	rec := &sink.Recorder{}
	EmitWiredTiger(rec, ss, time.Now())
	wantNames(t, rec, "mongodb.wiredtiger.cache.bytes", "mongodb.wiredtiger.cache.max_bytes",
		"mongodb.wiredtiger.cache.app_evictions", "mongodb.wiredtiger.tickets.write.available", "mongodb.latency.total")
	if w := OplogWindow(bson.Timestamp{T: 1000}, bson.Timestamp{T: 4600, I: 3}); w != 3600 {
		t.Fatal(w)
	}
	ops := []bson.D{{{Key: "op", Value: "update"}, {Key: "ns", Value: "shop.orders"}, {Key: "microsecs_running", Value: int64(4_000_000)},
		{Key: "waitingForLock", Value: true}, {Key: "command", Value: bson.D{{Key: "q", Value: bson.D{{Key: "_id", Value: int32(42)}}}}}}}
	rec = &sink.Recorder{}
	EmitCurrentOp(rec, ops, time.Now())
	if v, _ := value(rec, "mongodb.operations.waiting_for_lock"); v != 1 {
		t.Fatal(v)
	}
	for _, s := range rec.Samples {
		if s.Name == "" && (strings.Contains(s.Body, `"_id":42`) || !strings.Contains(s.Body, `"running_ms":4000`)) {
			t.Fatalf("sample %s", s.Body)
		}
	}
}

func TestMongoIndexAndCollectionStats(t *testing.T) {
	rec := &sink.Recorder{}
	EmitIndexStats(rec, "shop", "orders", []bson.D{{{Key: "name", Value: "status_1"},
		{Key: "accesses", Value: bson.D{{Key: "ops", Value: int64(0)}}}}}, time.Now())
	EmitCollStats(rec, "shop", "orders", []bson.D{{{Key: "storageStats", Value: bson.D{{Key: "size", Value: int64(10)},
		{Key: "count", Value: int32(2)}, {Key: "totalIndexSize", Value: int64(4)}}}}}, time.Now())
	wantNames(t, rec, "mongodb.index.accesses", "mongodb.collection.size", "mongodb.collection.documents", "mongodb.collection.index_size")
	if rec.Samples[0].Attrs["mongodb.index.name"] != "status_1" {
		t.Fatalf("%+v", rec.Samples[0].Attrs)
	}
}
