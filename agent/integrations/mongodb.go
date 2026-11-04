package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MongoConfig is the mongodb module's config. URI (with credentials) is local-file only.
type MongoConfig struct {
	Base
	URI string `json:"uri"`
	// Databases whose profiler, index and collection stats are read; default every non-system one (at most 20).
	Databases []string `json:"databases"`
	// SlowMs is the running time past which an operation is sampled (default 1000).
	SlowMs int `json:"slow_ms"`
}

func (c *MongoConfig) check() error {
	if c.URI == "" {
		return errors.New("mongodb: uri is required (in the agent's own config file)")
	}
	return nil
}

// MongoDB runs serverStatus and replSetGetStatus, then the deeper reads of mongodb_dbm.go.
func MongoDB(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &MongoConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	cl, err := mongo.Connect(options.Client().ApplyURI(c.URI).SetServerSelectionTimeout(5 * time.Second))
	if err != nil {
		return err
	}
	defer cl.Disconnect(context.Background())
	deep := newMongoDeep(c.SlowMs)
	return Loop(ctx, "mongodb", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		admin := cl.Database("admin")
		var ss bson.D
		if err := admin.RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&ss); err != nil {
			return err
		}
		if !EmitServerStatus(out, ss, now) {
			// An empty or unrecognised reply must not read as a healthy server.
			return errors.New("mongodb: serverStatus has no connection metrics")
		}
		EmitWiredTiger(out, ss, now)
		var rs bson.D
		// Not a replica set member: the command errors and there is no lag to report.
		replica := admin.RunCommand(ctx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&rs) == nil
		if replica {
			EmitReplSet(out, rs, now)
		}
		deep.collect(ctx, cl, out, mongoDatabases(ctx, cl, c.Databases), replica, now)
		return nil
	})
}

// get reads one key of a bson.D or bson.M. The v2 driver decodes nested documents as bson.D
// whatever the target type was, so both shapes must be walked.
func get(doc any, key string) (any, bool) {
	switch d := doc.(type) {
	case bson.D:
		for _, e := range d {
			if e.Key == key {
				return e.Value, true
			}
		}
	case bson.M:
		v, ok := d[key]
		return v, ok
	case map[string]any: // toJSON output
		v, ok := d[key]
		return v, ok
	}
	return nil, false
}

// dig walks nested documents.
func dig(doc any, keys ...string) (any, bool) {
	for _, k := range keys {
		var ok bool
		if doc, ok = get(doc, k); !ok {
			return nil, false
		}
	}
	return doc, true
}

// num reads a nested number (int32, int64 or double).
func num(doc any, keys ...string) (float64, bool) {
	v, ok := dig(doc, keys...)
	if !ok {
		return 0, false
	}
	switch v := v.(type) {
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// EmitServerStatus emits connections, opcounters and memory from a serverStatus reply (bson.D
// or bson.M). It reports whether the connection counts were present.
func EmitServerStatus(out sink.Sink, ss any, now time.Time) bool {
	g := func(name string, keys ...string) bool {
		v, ok := num(ss, keys...)
		if ok {
			out.Gauge(name, "1", v, nil, now)
		}
		return ok
	}
	core := g("mongodb.connections.current", "connections", "current")
	g("mongodb.connections.available", "connections", "available")
	g("mongodb.memory.resident", "mem", "resident")
	g("mongodb.uptime", "uptime")
	for _, op := range []string{"insert", "query", "update", "delete", "command"} {
		if v, ok := num(ss, "opcounters", op); ok {
			out.Sum("mongodb.operations", "{operations}", v, map[string]string{"operation": op}, now)
		}
	}
	// Query executor work (APM-024): index keys and documents scanned, collection scans and
	// in-memory sorts, the signals of a missing index.
	for _, m := range []struct {
		name, unit string
		keys       []string
	}{
		{"mongodb.query_executor.scanned", "{keys}", []string{"metrics", "queryExecutor", "scanned"}},
		{"mongodb.query_executor.scanned_objects", "{documents}", []string{"metrics", "queryExecutor", "scannedObjects"}},
		{"mongodb.query_executor.collection_scans", "{scans}", []string{"metrics", "queryExecutor", "collectionScans", "total"}},
		{"mongodb.query_executor.collection_scans.non_tailable", "{scans}", []string{"metrics", "queryExecutor", "collectionScans", "nonTailable"}},
		{"mongodb.operation.scan_and_order", "{operations}", []string{"metrics", "operation", "scanAndOrder"}},
	} {
		if v, ok := num(ss, m.keys...); ok {
			out.Sum(m.name, m.unit, v, nil, now)
		}
	}
	return core
}

// EmitReplSet emits each member's health and its optime lag behind the primary.
func EmitReplSet(out sink.Sink, rs any, now time.Time) {
	arr, _ := dig(rs, "members")
	members, _ := arr.(bson.A)
	type member struct {
		name   string
		state  string
		health float64
		optime time.Time
	}
	var ms []member
	var primary time.Time
	for _, d := range members {
		m := member{}
		if v, ok := get(d, "name"); ok {
			m.name, _ = v.(string)
		}
		if v, ok := get(d, "stateStr"); ok {
			m.state, _ = v.(string)
		}
		m.health, _ = num(d, "health")
		if v, ok := get(d, "optimeDate"); ok {
			if t, ok := v.(bson.DateTime); ok {
				m.optime = t.Time()
			}
		}
		if m.state == "PRIMARY" {
			primary = m.optime
		}
		ms = append(ms, m)
	}
	for _, m := range ms {
		a := map[string]string{"member": m.name, "state": m.state}
		out.Gauge("mongodb.replset.member.health", "1", m.health, a, now)
		if !primary.IsZero() && !m.optime.IsZero() && m.state != "PRIMARY" {
			out.Gauge("mongodb.replset.lag", "s", max(primary.Sub(m.optime).Seconds(), 0), a, now)
		}
	}
}
