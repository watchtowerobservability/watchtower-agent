package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// PodCheck is one integration module an annotated pod asks for (k8s.CheckTarget without the
// k8s types, so this package stays free of the Kubernetes client).
type PodCheck struct {
	Namespace, Pod, UID, Container, Module string
	PodIP                                  string
	Config                                 map[string]any
}

// podModules are the modules a pod annotation may start. Left out: listen and docker (they read
// the agent's own host) and http_status (an annotation must not make the agent probe a URL).
var podModules = map[string]func(context.Context, json.RawMessage, sink.Sink) error{
	"postgres": Postgres, "mysql": MySQL, "redis": Redis, "memcached": Memcached, "mongodb": MongoDB,
	"kafka": Kafka, "rabbitmq": RabbitMQ, "nats": NATS, "emqx": EMQX, "mosquitto": Mosquitto, "mssql": MSSQL, "oracle": Oracle,
	"cassandra": Cassandra, "consul": Consul, "vault": Vault, "jmx": JMX, "activemq": ActiveMQ, "artemis": Artemis,
	"ceph": Ceph, "pulsar": Pulsar, "kinesis": Kinesis, "qdrant": Qdrant, "weaviate": Weaviate, "milvus": Milvus,
	"couchbase": Couchbase, "traefik": Traefik, "envoy": Envoy, "jenkins": Jenkins, "gitlab": GitLab, "iis": IIS,
	"tomcat": Tomcat, "kong": Kong, "minio": MinIO, "zookeeper": Zookeeper, "solr": Solr, "nomad": Nomad, "istio": Istio,
}

// podKey is the config key a module takes its target from, for the `host`/`port` shorthand.
var podKey = map[string]string{
	"postgres": "", "mysql": "", "mongodb": "", // DSN and URI modules need the full string
	"redis": "addr", "memcached": "addr", "kafka": "brokers", "mosquitto": "addr", "emqx": "url",
	"rabbitmq": "url", "nats": "url", "mssql": "url", "oracle": "url", "cassandra": "url",
	"consul": "url", "vault": "url", "jmx": "url", "activemq": "url", "artemis": "url", "ceph": "url", "pulsar": "url", "kinesis": "url",
	"qdrant": "url", "weaviate": "url", "milvus": "url",
	"couchbase": "url", "traefik": "url", "envoy": "url", "jenkins": "url", "gitlab": "url", "iis": "url",
	"tomcat": "url", "kong": "url", "minio": "url", "zookeeper": "url", "solr": "url", "nomad": "url", "istio": "url",
}

// NormalizePodConfig turns an annotation config into the module's own config: the first entry of
// `instances` is merged over the top level, and `host` plus `port` become the module's address.
func NormalizePodConfig(module string, cfg map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range cfg {
		if k != "instances" {
			out[k] = v
		}
	}
	if is, _ := cfg["instances"].([]any); len(is) > 0 {
		if m, ok := is[0].(map[string]any); ok {
			for k, v := range m {
				out[k] = v
			}
		}
	}
	h, _ := out["host"].(string)
	port := fmt.Sprint(out["port"])
	delete(out, "host")
	delete(out, "port")
	if k := podKey[module]; h != "" && k != "" {
		addr := h
		if port != "" && port != "<nil>" && port != "0" {
			addr = net.JoinHostPort(h, port)
		}
		switch k {
		case "brokers":
			out[k] = []any{addr}
		case "url":
			if _, set := out[k]; !set {
				out[k] = "http://" + addr
			}
		default:
			if _, set := out[k]; !set {
				out[k] = addr
			}
		}
	}
	return out
}

var parenRE = regexp.MustCompile(`\(([^)]*)\)`)

// hostOf extracts the host from a URL, a Go MySQL DSN (`u:p@tcp(h:3306)/db`), a libpq key=value
// DSN or a host:port. ok is false when it cannot tell.
func hostOf(s string) (string, bool) {
	switch {
	case strings.Contains(s, "://"):
		u, err := url.Parse(s)
		if err != nil {
			return "", false
		}
		return u.Hostname(), u.Hostname() != ""
	case strings.Contains(s, "tcp("):
		m := parenRE.FindStringSubmatch(s)
		if m == nil {
			return "", false
		}
		s = m[1]
	case strings.Contains(s, "host="):
		for _, f := range strings.Fields(s) {
			if v, ok := strings.CutPrefix(f, "host="); ok {
				return v, v != ""
			}
		}
		return "", false
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h, h != ""
	}
	return s, s != "" && !strings.ContainsAny(s, " /@")
}

// checkTargetsPod refuses a config whose target is not the annotated pod itself, so an
// annotation can never aim the agent at another workload or the node.
func checkTargetsPod(cfg map[string]any, ip string) error {
	found := false
	for _, k := range []string{"addr", "url", "dsn", "uri", "brokers"} {
		var vals []string
		switch v := cfg[k].(type) {
		case string:
			vals = []string{v}
		case []any:
			for _, e := range v {
				vals = append(vals, fmt.Sprint(e))
			}
		}
		for _, s := range vals {
			found = true
			if h, ok := hostOf(s); !ok || h != ip {
				return fmt.Errorf("%s must point at the pod itself", k)
			}
		}
	}
	if !found {
		return errors.New("no target (host/port, addr, url, dsn, uri or brokers)")
	}
	return nil
}

// labeled adds the pod's identity (as resource attributes) to everything a module emits.
type labeled struct {
	sink.Sink
	a map[string]string
}

func (l labeled) Gauge(n, u string, v float64, a map[string]string, at time.Time) {
	l.Sink.Gauge(n, u, v, sink.With(a, kvs(l.a)...), at)
}

func (l labeled) Sum(n, u string, v float64, a map[string]string, at time.Time) {
	l.Sink.Sum(n, u, v, sink.With(a, kvs(l.a)...), at)
}

func (l labeled) Log(sev, body string, a map[string]string, at time.Time) {
	l.Sink.Log(sev, body, sink.With(a, kvs(l.a)...), at)
}

func kvs(m map[string]string) []string {
	out := make([]string, 0, 2*len(m))
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}

type podRun struct {
	cancel context.CancelFunc
	hash   string
}

// RunAnnotated keeps one running module per annotated pod container. Every interval it asks list
// for the current bindings, starts the new ones, restarts a changed one and stops the ones whose
// pod is gone. A rejected binding is logged once per change and skipped.
func RunAnnotated(ctx context.Context, list func() []PodCheck, out sink.Sink, every time.Duration) {
	running := map[string]podRun{}
	rejected := map[string]string{}
	defer func() {
		for _, r := range running {
			r.cancel()
		}
	}()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		want := map[string]PodCheck{}
		for _, pc := range list() {
			want[pc.UID+"/"+pc.Container+"/"+pc.Module] = pc
		}
		for k, r := range running {
			if _, ok := want[k]; !ok {
				r.cancel()
				delete(running, k)
			}
		}
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			startPodCheck(ctx, k, want[k], running, rejected, out)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func startPodCheck(ctx context.Context, key string, pc PodCheck, running map[string]podRun, rejected map[string]string, out sink.Sink) {
	cfg := NormalizePodConfig(pc.Module, pc.Config)
	raw, _ := json.Marshal(cfg)
	hash := strconv.Itoa(len(raw)) + string(raw)
	if r, ok := running[key]; ok {
		if r.hash == hash {
			return
		}
		r.cancel()
		delete(running, key)
	}
	run := podModules[pc.Module]
	err := checkTargetsPod(cfg, pc.PodIP)
	if run == nil {
		err = fmt.Errorf("module %q cannot be started from an annotation", pc.Module)
	}
	if err != nil {
		if rejected[key] != hash {
			rejected[key] = hash
			slog.Warn("pod check rejected", "pod", pc.Namespace+"/"+pc.Pod, "container", pc.Container, "module", pc.Module, "error", err)
		}
		return
	}
	delete(rejected, key)
	cctx, cancel := context.WithCancel(ctx)
	running[key] = podRun{cancel: cancel, hash: hash}
	o := labeled{out, sink.Res(map[string]string{
		"k8s.namespace.name": pc.Namespace, "k8s.pod.name": pc.Pod, "k8s.pod.uid": pc.UID, "k8s.container.name": pc.Container,
	})}
	go func() {
		if err := run(cctx, raw, o); err != nil && cctx.Err() == nil {
			slog.Warn("pod check stopped", "pod", pc.Namespace+"/"+pc.Pod, "module", pc.Module, "error", sink.Truncate(err.Error(), 200))
		}
	}()
}
