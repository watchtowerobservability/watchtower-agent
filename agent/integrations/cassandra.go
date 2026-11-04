package integrations

// Cassandra and ScyllaDB depth (track A2). Cassandra: through a Jolokia agent (url ending in
// /jolokia) the module reads per-table read/write latency, tombstones and SSTables per read,
// pending compactions and live disk, compaction totals, coordinator latency, timeouts and
// unavailables, thread pool backlog and dropped messages; any other url is scraped as the
// cassandra-exporter or JMX exporter. ScyllaDB: its own Prometheus endpoint (port 9180).

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Cassandra reads MBeans through Jolokia, or scrapes an exporter.
func Cassandra(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &ExporterConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if u, _ := url.Parse(c.URL); !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/jolokia") {
		return runExporter(ctx, exporterSpec{name: "cassandra", prefixes: []string{"cassandra_"}, interval: 30 * time.Second}, raw, out)
	}
	hc := HTTPConfig{URL: strings.TrimRight(c.URL, "/"), Username: c.Username, Password: c.Password}
	return Loop(ctx, "cassandra", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		rs, err := jolokiaRead(ctx, hc, cassandraReads)
		if err != nil {
			return err
		}
		EmitCassandraJMX(out, rs, now)
		return nil
	})
}

// ScyllaDB scrapes the node's Prometheus endpoint (default http://host:9180/metrics).
func ScyllaDB(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "scylladb", prefixes: []string{"scylla_"}, path: "/metrics", interval: 30 * time.Second}, raw, out)
}

const cm = "org.apache.cassandra.metrics:"

var cassandraTableNames = []string{"ReadLatency", "WriteLatency", "TombstoneScannedHistogram", "SSTablesPerReadHistogram",
	"PendingCompactions", "LiveDiskSpaceUsed"}

var cassandraReads = func() []MBeanRead {
	var rs []MBeanRead
	for _, n := range cassandraTableNames {
		rs = append(rs, MBeanRead{MBean: cm + "type=Table,keyspace=*,scope=*,name=" + n, Attributes: []string{"Count", "99thPercentile", "Max", "Value"}})
	}
	return append(rs,
		MBeanRead{MBean: cm + "type=Compaction,name=*", Attributes: []string{"Value", "Count"}},
		MBeanRead{MBean: cm + "type=ClientRequest,scope=*,name=*", Attributes: []string{"Count", "99thPercentile"}},
		MBeanRead{MBean: cm + "type=ThreadPools,path=*,scope=*,name=*", Attributes: []string{"Value", "Count"}},
		MBeanRead{MBean: cm + "type=DroppedMessage,scope=*,name=Dropped", Attributes: []string{"Count"}},
	)
}()

// cassandraSystemKeyspaces are left out of the per-table series.
var cassandraSystemKeyspaces = map[string]bool{"system": true, "system_schema": true, "system_auth": true,
	"system_distributed": true, "system_traces": true, "system_virtual_schema": true, "system_views": true}

const cassandraMaxTables = 300

func fnum(m map[string]any, k string) (float64, bool) {
	f, ok := m[k].(float64)
	return f, ok
}

// EmitCassandraJMX turns the Jolokia responses of cassandraReads into series.
func EmitCassandraJMX(out sink.Sink, rs []jolokiaResp, now time.Time) {
	tables := map[string]bool{}
	for _, r := range rs {
		perMBean(r, func(mbean string, attrs map[string]any) {
			p := mbeanProps(mbean)
			switch p["type"] {
			case "Table":
				emitCassandraTable(out, p, attrs, tables, now)
			case "Compaction":
				switch p["name"] {
				case "PendingTasks":
					if v, ok := fnum(attrs, "Value"); ok {
						out.Gauge("cassandra.compaction.pending", "{tasks}", v, nil, now)
					}
				case "CompletedTasks":
					if v, ok := fnum(attrs, "Value"); ok {
						out.Sum("cassandra.compaction.completed", "{tasks}", v, nil, now)
					}
				case "BytesCompacted":
					if v, ok := fnum(attrs, "Count"); ok {
						out.Sum("cassandra.compaction.bytes", "By", v, nil, now)
					}
				}
			case "ClientRequest":
				a := map[string]string{"db.operation.name": strings.ToLower(p["scope"])}
				switch p["name"] {
				case "Latency":
					if v, ok := fnum(attrs, "99thPercentile"); ok {
						out.Gauge("cassandra.client_request.latency.p99", "us", v, a, now)
					}
					if v, ok := fnum(attrs, "Count"); ok {
						out.Sum("cassandra.client_request.count", "{requests}", v, a, now)
					}
				case "Timeouts", "Unavailables", "Failures":
					if v, ok := fnum(attrs, "Count"); ok {
						out.Sum("cassandra.client_request."+strings.ToLower(p["name"]), "{requests}", v, a, now)
					}
				}
			case "ThreadPools":
				a := map[string]string{"thread_pool": p["scope"]}
				switch p["name"] {
				case "PendingTasks":
					if v, ok := fnum(attrs, "Value"); ok {
						out.Gauge("cassandra.thread_pool.pending", "{tasks}", v, a, now)
					}
				case "CurrentlyBlockedTasks":
					if v, ok := fnum(attrs, "Count"); ok {
						out.Gauge("cassandra.thread_pool.blocked", "{tasks}", v, a, now)
					}
				}
			case "DroppedMessage":
				if v, ok := fnum(attrs, "Count"); ok {
					out.Sum("cassandra.dropped_messages", "{messages}", v, map[string]string{"verb": p["scope"]}, now)
				}
			}
		})
	}
}

func emitCassandraTable(out sink.Sink, p map[string]string, attrs map[string]any, tables map[string]bool, now time.Time) {
	if cassandraSystemKeyspaces[p["keyspace"]] {
		return
	}
	key := p["keyspace"] + "." + p["scope"]
	if !tables[key] {
		if len(tables) >= cassandraMaxTables {
			return
		}
		tables[key] = true
	}
	a := map[string]string{"db.namespace": p["keyspace"], "db.collection.name": p["scope"]}
	g := func(name, unit, attr string) {
		if v, ok := fnum(attrs, attr); ok {
			out.Gauge(name, unit, v, a, now)
		}
	}
	switch p["name"] {
	case "ReadLatency", "WriteLatency":
		op := strings.ToLower(strings.TrimSuffix(p["name"], "Latency"))
		g("cassandra.table."+op+".latency.p99", "us", "99thPercentile")
		if v, ok := fnum(attrs, "Count"); ok {
			out.Sum("cassandra.table."+op+"s", "{requests}", v, a, now)
		}
	case "TombstoneScannedHistogram":
		g("cassandra.table.tombstones_scanned.p99", "{tombstones}", "99thPercentile")
		g("cassandra.table.tombstones_scanned.max", "{tombstones}", "Max")
	case "SSTablesPerReadHistogram":
		g("cassandra.table.sstables_per_read.p99", "{sstables}", "99thPercentile")
	case "PendingCompactions":
		g("cassandra.table.pending_compactions", "{tasks}", "Value")
	case "LiveDiskSpaceUsed":
		g("cassandra.table.disk.live", "By", "Count")
	}
}
