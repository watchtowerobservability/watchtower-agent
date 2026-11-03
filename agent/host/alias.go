package host

import (
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Emit modes for Config.Emit.
const (
	EmitOTel         = "otel"          // semconv names only (default)
	EmitNodeExporter = "node_exporter" // node_* names only
	EmitBoth         = "both"
)

// alias is how one semconv sample maps onto a node_exporter series.
type alias struct {
	name   string
	rename map[string]string // attribute renames
	match  map[string]string // attribute values the source sample must have
	drop   []string          // attributes removed (folded into the name)
}

func (a alias) matches(attrs map[string]string) bool {
	for k, v := range a.match {
		if attrs[k] != v {
			return false
		}
	}
	return true
}

// nodeAliases maps a semconv metric name to its node_exporter series, so community node_exporter
// dashboards work unchanged. Series node_exporter has no equivalent for (CPU percent) are not aliased.
var nodeAliases = map[string][]alias{
	"system.cpu.load_average.1m":  {{name: "node_load1"}},
	"system.cpu.load_average.5m":  {{name: "node_load5"}},
	"system.cpu.load_average.15m": {{name: "node_load15"}},
	"system.memory.limit":         {{name: "node_memory_MemTotal_bytes"}},
	"system.memory.usage": {
		{name: "node_memory_MemAvailable_bytes", match: map[string]string{"state": "free"}, drop: []string{"state"}},
	},
	"system.filesystem.limit": {{name: "node_filesystem_size_bytes", rename: map[string]string{"type": "fstype"}}},
	"system.filesystem.usage": {
		{name: "node_filesystem_avail_bytes", match: map[string]string{"state": "free"}, rename: map[string]string{"type": "fstype"}, drop: []string{"state"}},
	},
	"system.disk.io": {
		{name: "node_disk_read_bytes_total", match: map[string]string{"direction": "read"}, drop: []string{"direction"}},
		{name: "node_disk_written_bytes_total", match: map[string]string{"direction": "write"}, drop: []string{"direction"}},
	},
	"system.cpu.time":             {{name: "node_cpu_seconds_total", rename: map[string]string{"cpu.logical_number": "cpu", "cpu.mode": "mode"}}},
	"system.cpu.context_switches": {{name: "node_context_switches_total"}},
	"system.processes.created":    {{name: "node_forks_total"}},
	"system.processes.count": {
		{name: "node_procs_running", match: map[string]string{"status": "running"}, drop: []string{"status"}},
		{name: "node_procs_blocked", match: map[string]string{"status": "blocked"}, drop: []string{"status"}},
	},
	"system.paging.limit": {{name: "node_memory_SwapTotal_bytes"}},
	"system.paging.usage": {
		{name: "node_memory_SwapFree_bytes", match: map[string]string{"state": "free"}, drop: []string{"state"}},
	},
	"system.paging.faults": {
		{name: "node_vmstat_pgmajfault", match: map[string]string{"type": "major"}, drop: []string{"type"}},
	},
	"system.filesystem.inodes.limit": {{name: "node_filesystem_files", rename: map[string]string{"type": "fstype"}}},
	"system.filesystem.inodes.usage": {
		{name: "node_filesystem_files_free", match: map[string]string{"state": "free"}, rename: map[string]string{"type": "fstype"}, drop: []string{"state"}},
	},
	"system.disk.operations": {
		{name: "node_disk_reads_completed_total", match: map[string]string{"direction": "read"}, drop: []string{"direction"}},
		{name: "node_disk_writes_completed_total", match: map[string]string{"direction": "write"}, drop: []string{"direction"}},
	},
	"system.disk.operation_time": {
		{name: "node_disk_read_time_seconds_total", match: map[string]string{"direction": "read"}, drop: []string{"direction"}},
		{name: "node_disk_write_time_seconds_total", match: map[string]string{"direction": "write"}, drop: []string{"direction"}},
	},
	"system.disk.merged": {
		{name: "node_disk_reads_merged_total", match: map[string]string{"direction": "read"}, drop: []string{"direction"}},
		{name: "node_disk_writes_merged_total", match: map[string]string{"direction": "write"}, drop: []string{"direction"}},
	},
	"system.disk.io_time":            {{name: "node_disk_io_time_seconds_total"}},
	"system.disk.weighted_io_time":   {{name: "node_disk_io_time_weighted_seconds_total"}},
	"system.disk.pending_operations": {{name: "node_disk_io_now"}},
	"system.network.packets": {
		{name: "node_network_receive_packets_total", match: map[string]string{"direction": "receive"}, drop: []string{"direction"}},
		{name: "node_network_transmit_packets_total", match: map[string]string{"direction": "transmit"}, drop: []string{"direction"}},
	},
	"system.network.errors": {
		{name: "node_network_receive_errs_total", match: map[string]string{"direction": "receive"}, drop: []string{"direction"}},
		{name: "node_network_transmit_errs_total", match: map[string]string{"direction": "transmit"}, drop: []string{"direction"}},
	},
	"system.network.dropped": {
		{name: "node_network_receive_drop_total", match: map[string]string{"direction": "receive"}, drop: []string{"direction"}},
		{name: "node_network_transmit_drop_total", match: map[string]string{"direction": "transmit"}, drop: []string{"direction"}},
	},
	"system.network.connections": {
		{name: "node_tcp_connection_states", match: map[string]string{"protocol": "tcp"}, drop: []string{"protocol"}},
	},
	"system.network.io": {
		{name: "node_network_receive_bytes_total", match: map[string]string{"direction": "receive"}, drop: []string{"direction"}},
		{name: "node_network_transmit_bytes_total", match: map[string]string{"direction": "transmit"}, drop: []string{"direction"}},
	},
}

// NodeAliasSink forwards to Inner and also (or only, when OnlyAlias) writes the node_exporter
// name for each sample that has one. A sample with no alias is always forwarded.
type NodeAliasSink struct {
	Inner     sink.Sink
	OnlyAlias bool
}

// WrapEmit returns out wrapped for the emit mode; an unknown or otel mode returns out itself.
func WrapEmit(out sink.Sink, mode string) sink.Sink {
	switch mode {
	case EmitNodeExporter:
		return NodeAliasSink{Inner: out, OnlyAlias: true}
	case EmitBoth:
		return NodeAliasSink{Inner: out}
	}
	return out
}

// each calls emit for every alias of name that matches attrs and reports whether any did.
func (n NodeAliasSink) each(name string, attrs map[string]string, emit func(string, map[string]string)) bool {
	hit := false
	for _, a := range nodeAliases[name] {
		if !a.matches(attrs) {
			continue
		}
		hit = true
		m := make(map[string]string, len(attrs))
		for k, v := range attrs {
			m[k] = v
		}
		for _, k := range a.drop {
			delete(m, k)
		}
		for from, to := range a.rename {
			if v, ok := m[from]; ok {
				delete(m, from)
				m[to] = v
			}
		}
		emit(a.name, m)
	}
	return hit
}

// Gauge implements sink.Sink.
func (n NodeAliasSink) Gauge(name, unit string, v float64, attrs map[string]string, at time.Time) {
	if !n.each(name, attrs, func(an string, am map[string]string) { n.Inner.Gauge(an, unit, v, am, at) }) || !n.OnlyAlias {
		n.Inner.Gauge(name, unit, v, attrs, at)
	}
}

// Sum implements sink.Sink.
func (n NodeAliasSink) Sum(name, unit string, v float64, attrs map[string]string, at time.Time) {
	if !n.each(name, attrs, func(an string, am map[string]string) { n.Inner.Sum(an, unit, v, am, at) }) || !n.OnlyAlias {
		n.Inner.Sum(name, unit, v, attrs, at)
	}
}

// Log implements sink.Sink.
func (n NodeAliasSink) Log(sev, body string, attrs map[string]string, at time.Time) {
	n.Inner.Log(sev, body, attrs, at)
}
