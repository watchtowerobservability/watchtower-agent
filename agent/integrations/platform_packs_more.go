package integrations

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Collector is a module body: it runs until ctx ends and reports through out.
type Collector = func(context.Context, json.RawMessage, sink.Sink) error

// exporterPackSpecs are the products that publish a Prometheus text endpoint (their own, or the
// well-known exporter next to them). The key is the module name and the manifest name.
var exporterPackSpecs = map[string]exporterSpec{
	"linkerd": {prefixes: []string{"request_total", "response_total", "tcp_open_connections", "tcp_open_total", "tcp_close_total", "identity_cert_expiry_timestamp_seconds"},
		path: "/metrics", rename: "linkerd_"}, // the proxy's admin port 4191; its names are unprefixed
	"phpfpm":        {prefixes: []string{"phpfpm_"}, path: "/metrics"},                                // hipages php-fpm_exporter
	"puma":          {prefixes: []string{"puma_"}, path: "/metrics"},                                  // yabeda-puma-plugin or puma-metrics
	"flink":         {prefixes: []string{"flink_"}, path: "/metrics"},                                 // PrometheusReporter, port 9249
	"spark":         {prefixes: []string{"metrics_executor_"}, path: "/metrics/executors/prometheus"}, // spark.ui.prometheus.enabled=true
	"aerospike":     {prefixes: []string{"aerospike_"}, path: "/metrics"},
	"varnish":       {prefixes: []string{"varnish_"}, path: "/metrics"},
	"uwsgi":         {prefixes: []string{"uwsgi_"}, path: "/metrics"},
	"cilium":        {prefixes: []string{"cilium_", "hubble_"}, path: "/metrics"},
	"calico":        {prefixes: []string{"felix_", "typha_"}, path: "/metrics"},
	"certmanager":   {prefixes: []string{"certmanager_"}, path: "/metrics"},
	"karpenter":     {prefixes: []string{"karpenter_"}, path: "/metrics"},
	"argocd":        {prefixes: []string{"argocd_"}, path: "/metrics"},
	"gitlab_runner": {prefixes: []string{"gitlab_runner_"}, path: "/metrics"},
	"fastly":        {prefixes: []string{"fastly_"}, path: "/metrics"},                                       // fastly-exporter
	"akamai":        {prefixes: []string{"akamai_"}, path: "/metrics"},                                       // an exporter republishing DataStream or Reporting API aggregates under akamai_*
	"atlas":         {prefixes: []string{"mongodb_"}, path: "/metrics", basic: true},                         // Atlas Prometheus integration, digest-less basic auth
	"confluent":     {prefixes: []string{"confluent_kafka_"}, path: "/v2/metrics/cloud/export", basic: true}, // Confluent Cloud Metrics API export
}

type jolokiaMetric struct {
	name, unit string
	sum        bool
}

type jolokiaPack struct {
	reads   []MBeanRead
	metrics map[string]jolokiaMetric // by MBean attribute
}

// jolokiaPacks are Java servers read through a Jolokia agent. A config `reads` list overrides the
// default reads (the attribute table still maps what comes back).
var jolokiaPacks = map[string]jolokiaPack{
	"jboss": {reads: []MBeanRead{
		{MBean: "jboss.as:subsystem=datasources,data-source=*,statistics=pool", Attributes: []string{"ActiveCount", "AvailableCount", "TimedOut"}},
		{MBean: "jboss.as:subsystem=undertow,server=*,http-listener=*", Attributes: []string{"requestCount", "errorCount", "processingTime"}},
	}, metrics: map[string]jolokiaMetric{
		"ActiveCount": {"jboss.datasource.active", "{connections}", false}, "AvailableCount": {"jboss.datasource.available", "{connections}", false},
		"TimedOut": {"jboss.datasource.timed_out", "{connections}", true}, "requestCount": {"jboss.undertow.requests", "{requests}", true},
		"errorCount": {"jboss.undertow.errors", "{requests}", true}, "processingTime": {"jboss.undertow.processing_time", "ms", true},
	}},
	"weblogic": {reads: []MBeanRead{
		{MBean: "com.bea:Type=ThreadPoolRuntime,*", Attributes: []string{"PendingUserRequestCount", "HoggingThreadCount", "ExecuteThreadIdleCount", "Throughput"}},
		{MBean: "com.bea:Type=JDBCDataSourceRuntime,*", Attributes: []string{"ActiveConnectionsCurrentCount", "WaitingForConnectionCurrentCount", "LeakedConnectionCount"}},
		{MBean: "com.bea:Type=ServerRuntime,*", Attributes: []string{"OpenSocketsCurrentCount"}},
	}, metrics: map[string]jolokiaMetric{
		"PendingUserRequestCount": {"weblogic.thread_pool.pending", "{requests}", false}, "HoggingThreadCount": {"weblogic.thread_pool.hogging", "{threads}", false},
		"ExecuteThreadIdleCount": {"weblogic.thread_pool.idle", "{threads}", false}, "Throughput": {"weblogic.thread_pool.throughput", "{requests}/s", false},
		"ActiveConnectionsCurrentCount": {"weblogic.jdbc.active", "{connections}", false}, "WaitingForConnectionCurrentCount": {"weblogic.jdbc.waiting", "{requests}", false},
		"LeakedConnectionCount": {"weblogic.jdbc.leaked", "{connections}", true}, "OpenSocketsCurrentCount": {"weblogic.sockets.open", "{sockets}", false},
	}},
	"hadoop": {reads: []MBeanRead{
		{MBean: "Hadoop:service=NameNode,name=FSNamesystem", Attributes: []string{"CapacityTotal", "CapacityUsed", "CapacityRemaining", "UnderReplicatedBlocks", "MissingBlocks", "CorruptBlocks"}},
		{MBean: "Hadoop:service=ResourceManager,name=QueueMetrics,q0=root", Attributes: []string{"AppsRunning", "AppsPending", "AvailableMB"}},
	}, metrics: map[string]jolokiaMetric{
		"CapacityTotal": {"hadoop.namenode.capacity_total", "By", false}, "CapacityUsed": {"hadoop.namenode.capacity_used", "By", false},
		"CapacityRemaining": {"hadoop.namenode.capacity_remaining", "By", false}, "UnderReplicatedBlocks": {"hadoop.namenode.under_replicated_blocks", "{blocks}", false},
		"MissingBlocks": {"hadoop.namenode.missing_blocks", "{blocks}", false}, "CorruptBlocks": {"hadoop.namenode.corrupt_blocks", "{blocks}", false},
		"AppsRunning": {"hadoop.yarn.apps_running", "{apps}", false}, "AppsPending": {"hadoop.yarn.apps_pending", "{apps}", false},
		"AvailableMB": {"hadoop.yarn.available_mb", "MiBy", false},
	}},
}

// emitMapped emits the attributes the table knows, labelled with the MBean's key properties.
func emitMapped(out sink.Sink, table map[string]jolokiaMetric, rs []jolokiaResp, now time.Time) {
	for _, r := range rs {
		perMBean(r, func(mbean string, attrs map[string]any) {
			labels := mbeanProps(mbean)
			for k, v := range attrs {
				m, ok := table[k]
				f, num := v.(float64)
				switch {
				case !ok || !num:
				case m.sum:
					out.Sum(m.name, m.unit, f, labels, now)
				default:
					out.Gauge(m.name, m.unit, f, labels, now)
				}
			}
		})
	}
}

// PackCollectors returns the collectors of the 2026-11 integration pack by module name: the
// Prometheus-endpoint products, the Jolokia servers, the host and status-page checks.
func PackCollectors() map[string]Collector {
	out := map[string]Collector{"systemd": Systemd, "ntp": NTP, "tlscert": TLSCert, "okta": Okta}
	for name, sp := range exporterPackSpecs {
		sp.name, sp.interval = name, packEvery
		out[name] = func(ctx context.Context, raw json.RawMessage, o sink.Sink) error { return runExporter(ctx, sp, raw, o) }
	}
	for name, jp := range jolokiaPacks {
		out[name] = func(ctx context.Context, raw json.RawMessage, o sink.Sink) error {
			return runJolokia(ctx, name, jp.reads, raw, o, func(s sink.Sink, rs []jolokiaResp, now time.Time) { emitMapped(s, jp.metrics, rs, now) })
		}
	}
	for name, sp := range statusPages {
		out[name] = func(ctx context.Context, raw json.RawMessage, o sink.Sink) error {
			return runStatusPage(ctx, name, sp, raw, o)
		}
	}
	return out
}

// PackNames is PackCollectors' keys, sorted.
func PackNames() []string {
	var names []string
	for n := range PackCollectors() {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CollectorFor returns the URL-driven collector for a manifest's module kind: the 2026-11 pack
// and the earlier Prometheus-endpoint packs. It is what `wtctl integration test` replays a
// recorded payload through; kinds that need a database connection return nil.
func CollectorFor(kind string) Collector {
	if c, ok := PackCollectors()[kind]; ok {
		return c
	}
	return map[string]Collector{"envoy": Envoy, "traefik": Traefik, "kong": Kong, "istio": Istio, "solr": Solr, "zookeeper": Zookeeper,
		"squid": Squid, "snowflake": Snowflake, "databricks": Databricks, "minio": MinIO, "nomad": Nomad, "couchbase": Couchbase, "gitlab": GitLab, "iis": IIS, "tomcat": Tomcat}[kind]
}
