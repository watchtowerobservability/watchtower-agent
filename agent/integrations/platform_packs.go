package integrations

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The packs below read a product's own Prometheus endpoint (or windows_exporter for IIS) through
// the shared exporter body; Tomcat goes through Jolokia and Jenkins through its JSON API.

const packEvery = 30 * time.Second

// Couchbase reads the native /metrics of Couchbase Server 7+ (port 8091, a read-only admin user).
func Couchbase(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "couchbase", prefixes: []string{"kv_", "cm_", "sys_", "index_", "n1ql_", "xdcr_", "couchbase_"},
		path: "/metrics", rename: "couchbase_", interval: packEvery, basic: true}, raw, out)
}

// Traefik reads the entrypoint's /metrics (metrics.prometheus enabled).
func Traefik(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "traefik", prefixes: []string{"traefik_"}, path: "/metrics", interval: packEvery}, raw, out)
}

// Envoy reads the admin listener's /stats/prometheus (port 9901).
func Envoy(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "envoy", prefixes: []string{"envoy_"}, path: "/stats/prometheus", interval: packEvery}, raw, out)
}

// GitLab reads /-/metrics of a self-managed instance (the agent's address on the monitoring allowlist).
func GitLab(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "gitlab", prefixes: []string{"gitlab_", "sidekiq_", "puma_", "http_requests_total"},
		path: "/-/metrics", rename: "gitlab_", interval: packEvery}, raw, out)
}

// IIS scrapes windows_exporter's iis collector.
func IIS(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "iis", prefixes: []string{"windows_iis_"}, path: "/metrics", interval: packEvery}, raw, out)
}

// Kong reads the Prometheus plugin's /metrics on the Admin or Status API.
func Kong(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "kong", prefixes: []string{"kong_"}, path: "/metrics", interval: packEvery}, raw, out)
}

// MinIO reads the cluster metrics (v2); Token is the bearer from `mc admin prometheus generate`.
func MinIO(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "minio", prefixes: []string{"minio_"}, path: "/minio/v2/metrics/cluster", interval: packEvery}, raw, out)
}

// Zookeeper reads the PrometheusMetricsProvider endpoint (port 7000); its names are unprefixed.
func Zookeeper(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "zookeeper", path: "/metrics", rename: "zookeeper_", interval: packEvery}, raw, out)
}

// Solr reads the solr-exporter (port 9854).
func Solr(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "solr", prefixes: []string{"solr_"}, path: "/metrics", interval: packEvery}, raw, out)
}

// Nomad reads /v1/metrics (telemetry.prometheus_metrics = true); Token is an ACL token.
func Nomad(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "nomad", prefixes: []string{"nomad_"},
		path: "/v1/metrics?format=prometheus", header: "X-Nomad-Token", interval: packEvery}, raw, out)
}

// Istio reads istiod's monitoring port (15014): xDS pushes, proxy convergence, cert signing.
func Istio(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runExporter(ctx, exporterSpec{name: "istio", prefixes: []string{"pilot_", "citadel_", "istio_"}, path: "/metrics", interval: packEvery}, raw, out)
}

// tomcatReads are Catalina's connector thread pools, request processors and session managers.
var tomcatReads = []MBeanRead{
	{MBean: "Catalina:type=ThreadPool,name=*", Attributes: []string{"currentThreadsBusy", "currentThreadCount", "maxThreads", "connectionCount"}},
	{MBean: "Catalina:type=GlobalRequestProcessor,name=*", Attributes: []string{"requestCount", "errorCount", "processingTime", "bytesSent", "bytesReceived"}},
	{MBean: "Catalina:type=Manager,host=*,context=*", Attributes: []string{"activeSessions", "rejectedSessions", "expiredSessions"}},
}

var tomcatMetric = map[string]struct {
	name, unit string
	sum        bool
}{
	"currentThreadsBusy": {"tomcat.threads.busy", "{threads}", false},
	"currentThreadCount": {"tomcat.threads.current", "{threads}", false},
	"maxThreads":         {"tomcat.threads.max", "{threads}", false},
	"connectionCount":    {"tomcat.connections", "{connections}", false},
	"requestCount":       {"tomcat.requests", "{requests}", true},
	"errorCount":         {"tomcat.errors", "{requests}", true},
	"processingTime":     {"tomcat.processing_time", "ms", true},
	"bytesSent":          {"tomcat.bytes_sent", "By", true},
	"bytesReceived":      {"tomcat.bytes_received", "By", true},
	"activeSessions":     {"tomcat.sessions.active", "{sessions}", false},
	"rejectedSessions":   {"tomcat.sessions.rejected", "{sessions}", true},
	"expiredSessions":    {"tomcat.sessions.expired", "{sessions}", true},
}

// Tomcat reads Catalina MBeans through a Jolokia agent (or the jolokia.war in webapps).
func Tomcat(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	return runJolokia(ctx, "tomcat", tomcatReads, raw, out, emitTomcat)
}

// emitTomcat labels connector series with `connector` and session series with `context`.
func emitTomcat(out sink.Sink, rs []jolokiaResp, now time.Time) {
	for _, r := range rs {
		perMBean(r, func(mbean string, attrs map[string]any) {
			p := mbeanProps(mbean)
			a := map[string]string{"connector": p["name"]}
			if p["type"] == "Manager" {
				a = map[string]string{"context": p["context"], "vhost": p["host"]}
			}
			for k, v := range attrs {
				m, ok := tomcatMetric[k]
				f, num := v.(float64)
				switch {
				case !ok || !num:
				case m.sum:
					out.Sum(m.name, m.unit, f, a, now)
				default:
					out.Gauge(m.name, m.unit, f, a, now)
				}
			}
		})
	}
}

// Jenkins reads the JSON API (a user and API token as username/password): executors, offline
// agents, the build queue and the last build of up to 500 jobs.
func Jenkins(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "jenkins", c.Base, 60*time.Second, out, func(ctx context.Context, now time.Time) error {
		comp, err := getBody(ctx, *c, c.URL+"/computer/api/json?tree=busyExecutors,totalExecutors,computer[displayName,offline,idle]")
		if err != nil {
			return err
		}
		queue, err := getBody(ctx, *c, c.URL+"/queue/api/json?tree=items[stuck,blocked,buildable,inQueueSince]")
		if err != nil {
			return err
		}
		jobs, err := getBody(ctx, *c, c.URL+"/api/json?tree=jobs[name,color,lastBuild[duration,result,timestamp]]{0,500}")
		if err != nil {
			return err
		}
		return EmitJenkins(out, comp, queue, jobs, now)
	})
}

// EmitJenkins turns the three API answers into jenkins.* series.
func EmitJenkins(out sink.Sink, comp, queue, jobs []byte, now time.Time) error {
	var c struct {
		Busy     float64 `json:"busyExecutors"`
		Total    float64 `json:"totalExecutors"`
		Computer []struct {
			Name    string `json:"displayName"`
			Offline bool   `json:"offline"`
		} `json:"computer"`
	}
	var q struct {
		Items []struct {
			Stuck   bool  `json:"stuck"`
			Blocked bool  `json:"blocked"`
			Since   int64 `json:"inQueueSince"`
		} `json:"items"`
	}
	var j struct {
		Jobs []struct {
			Name      string `json:"name"`
			Color     string `json:"color"`
			LastBuild *struct {
				Duration float64 `json:"duration"`
				Result   string  `json:"result"`
				At       int64   `json:"timestamp"`
			} `json:"lastBuild"`
		} `json:"jobs"`
	}
	for _, d := range []struct {
		b []byte
		v any
	}{{comp, &c}, {queue, &q}, {jobs, &j}} {
		if err := json.Unmarshal(d.b, d.v); err != nil {
			return err
		}
	}
	none := map[string]string{}
	out.Gauge("jenkins.executors.busy", "{executors}", c.Busy, none, now)
	out.Gauge("jenkins.executors.total", "{executors}", c.Total, none, now)
	offline := 0.0
	for _, n := range c.Computer {
		v := 0.0
		if n.Offline {
			v, offline = 1, offline+1
		}
		out.Gauge("jenkins.node.offline", "1", v, map[string]string{"node": n.Name}, now)
	}
	out.Gauge("jenkins.nodes.offline", "{nodes}", offline, none, now)
	stuck, blocked, oldest := 0.0, 0.0, 0.0
	for _, it := range q.Items {
		if it.Stuck {
			stuck++
		}
		if it.Blocked {
			blocked++
		}
		if it.Since > 0 {
			oldest = max(oldest, now.Sub(time.UnixMilli(it.Since)).Seconds())
		}
	}
	out.Gauge("jenkins.queue.size", "{items}", float64(len(q.Items)), none, now)
	out.Gauge("jenkins.queue.stuck", "{items}", stuck, none, now)
	out.Gauge("jenkins.queue.blocked", "{items}", blocked, none, now)
	out.Gauge("jenkins.queue.oldest_wait", "s", oldest, none, now)
	for _, jb := range j.Jobs {
		if jb.LastBuild == nil || jb.LastBuild.Result == "" { // never built, or still running
			continue
		}
		a := map[string]string{"job": jb.Name, "result": strings.ToLower(jb.LastBuild.Result)}
		ok := 0.0
		if jb.LastBuild.Result == "SUCCESS" {
			ok = 1
		}
		out.Gauge("jenkins.job.last_build.success", "1", ok, a, now)
		out.Gauge("jenkins.job.last_build.duration", "s", jb.LastBuild.Duration/1000, a, now)
	}
	return nil
}
