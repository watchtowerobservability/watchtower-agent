package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/watchtowerobservability/watchtower-agent/agent/integrations"
	"github.com/watchtowerobservability/watchtower-agent/agent/logs"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	saDir         = "/var/run/secrets/kubernetes.io/serviceaccount"
	resyncPeriod  = 10 * time.Minute
	minInterval   = 5 * time.Second
	logTailEvery  = time.Second
	attrCacheTTL  = 30 * time.Second
	attrCacheSize = 2000
)

// syncTimeout bounds the wait for informer caches (a variable so tests can shorten it).
var syncTimeout = 60 * time.Second

// NodeConfig is the node agent's config. Only Enabled and Interval can be set remotely; the
// kubelet address, credentials and log directory live in the agent's own file.
type NodeConfig struct {
	Enabled         *bool  `json:"enabled"`
	Interval        string `json:"interval"`     // default 30s, at least 5s
	ClusterName     string `json:"cluster_name"` // k8s.cluster.name on everything
	NodeName        string `json:"node_name"`    // default $NODE_NAME
	KubeletURL      string `json:"kubelet_url"`  // default https://$NODE_IP:10250
	KubeletCAFile   string `json:"kubelet_ca_file"`
	KubeletInsecure bool   `json:"kubelet_insecure_tls"`
	TokenFile       string `json:"token_file"`
	PodLogDir       string `json:"pod_log_dir"` // default /var/log/pods; "off" disables log tailing
	Cadvisor        *bool  `json:"cadvisor"`    // kubelet /metrics/cadvisor container_* series; default true

	cadvisor func(context.Context) (map[string]*dto.MetricFamily, error) // set by RunNode
}

func (c *NodeConfig) defaults() error {
	if c.NodeName == "" {
		c.NodeName = os.Getenv("NODE_NAME")
	}
	if c.NodeName == "" {
		return errors.New("k8s_node: node_name (or $NODE_NAME) is required")
	}
	if c.KubeletURL == "" {
		host := os.Getenv("NODE_IP")
		if host == "" {
			// Without verification the token must not follow a DNS name off the node.
			if c.KubeletInsecure {
				return errors.New("k8s_node: NODE_IP (status.hostIP) is required when kubelet_insecure_tls is set")
			}
			host = c.NodeName
		}
		c.KubeletURL = "https://" + host + ":10250"
	}
	if c.TokenFile == "" {
		c.TokenFile = filepath.Join(saDir, "token")
	}
	if c.PodLogDir == "" {
		c.PodLogDir = "/var/log/pods"
	}
	return nil
}

// Duration parses s, falling back to def and never going below floor.
func Duration(s string, def, floor time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		d = def
	}
	if d < floor {
		d = floor
	}
	return d
}

// RunNode runs the node agent against the in-cluster API until ctx ends.
func RunNode(ctx context.Context, raw json.RawMessage, stateDir string, out sink.Sink) error {
	var c NodeConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	if err := c.defaults(); err != nil {
		return err
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("k8s_node: %w", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	out = sink.Hoist(out)
	kl, err := NewKubelet(c.KubeletURL, c.TokenFile, c.KubeletCAFile, c.KubeletInsecure)
	if err != nil {
		return err
	}
	if c.Cadvisor == nil || *c.Cadvisor {
		c.cadvisor = kl.Cadvisor
	}
	return runNode(ctx, c, cs, kl.Summary, stateDir, out)
}

type nodeAgent struct {
	cfg   NodeConfig
	pods  cache.Indexer
	look  Lookup
	out   sink.Sink
	mu    sync.Mutex
	attrs map[string]cachedAttrs
}

type cachedAttrs struct {
	a  map[string]string
	at time.Time
}

const uidIndex = "uid"

func runNode(ctx context.Context, cfg NodeConfig, cs kubernetes.Interface,
	summary func(context.Context) (*Summary, error), stateDir string, out sink.Sink) error {
	// Only the pods of this node are listed and watched, so memory stays flat as the cluster grows.
	f := informers.NewSharedInformerFactoryWithOptions(cs, resyncPeriod,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", cfg.NodeName).String()
		}))
	inf := f.Core().V1().Pods().Informer()
	if err := inf.SetTransform(Trim); err != nil {
		return err
	}
	if err := inf.AddIndexers(cache.Indexers{uidIndex: func(o any) ([]string, error) {
		if p, ok := o.(*corev1.Pod); ok {
			return []string{string(p.UID)}, nil
		}
		return nil, nil
	}}); err != nil {
		return err
	}
	f.Start(ctx.Done())
	sctx, cancel := context.WithTimeout(ctx, syncTimeout)
	ok := cache.WaitForCacheSync(sctx.Done(), inf.HasSynced)
	cancel()
	if !ok {
		return errors.New("k8s_node: pod cache did not sync")
	}
	n := &nodeAgent{cfg: cfg, pods: inf.GetIndexer(), look: NewAPILookup(cs), out: out, attrs: map[string]cachedAttrs{}}
	if cfg.PodLogDir != "off" {
		go n.tailLogs(ctx, stateDir)
	}
	go integrations.RunAnnotated(ctx, n.podChecks, out, 30*time.Second)
	t := time.NewTicker(Duration(cfg.Interval, 30*time.Second, minInterval))
	defer t.Stop()
	for {
		n.poll(ctx, summary)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (n *nodeAgent) poll(ctx context.Context, summary func(context.Context) (*Summary, error)) {
	var list []*corev1.Pod
	for _, o := range n.pods.List() {
		if p, ok := o.(*corev1.Pod); ok {
			list = append(list, p)
		}
	}
	t := Discover(list)
	discovered.Store(&t)
	s, err := summary(ctx)
	if err != nil {
		slog.Warn("kubelet summary unavailable", "error", err)
		return
	}
	res := map[string]string{"k8s.node.name": n.cfg.NodeName, "host.name": n.cfg.NodeName}
	if n.cfg.ClusterName != "" {
		res["k8s.cluster.name"] = n.cfg.ClusterName
	}
	if n.cfg.cadvisor != nil {
		if fams, err := n.cfg.cadvisor(ctx); err != nil {
			slog.Warn("kubelet cadvisor unavailable", "error", err)
		} else {
			EmitCadvisor(n.out, fams, n.cfg.NodeName, n.cfg.ClusterName, time.Now())
		}
	}
	Emit(n.out, s, res, func(r PodRef) map[string]string { return n.podAttrs(ctx, r.UID, r.Namespace, r.Name) }, time.Now())
}

// podAttrs are the enrichment attributes of the pod with this uid (owner chain included),
// cached for 30 s. A pod the cache does not know (already gone) gets its identity from the
// caller's namespace and name.
func (n *nodeAgent) podAttrs(ctx context.Context, uid, ns, name string) map[string]string {
	n.mu.Lock()
	c, ok := n.attrs[uid]
	n.mu.Unlock()
	if ok && time.Since(c.at) < attrCacheTTL {
		return c.a
	}
	var a map[string]string
	if objs, err := n.pods.ByIndex(uidIndex, uid); err == nil && len(objs) > 0 {
		if p, ok := objs[0].(*corev1.Pod); ok {
			a = PodAttrs(ctx, n.cfg.ClusterName, p, n.look)
		}
	}
	if a == nil {
		a = map[string]string{"k8s.namespace.name": ns, "k8s.pod.name": name, "k8s.pod.uid": uid, "k8s.node.name": n.cfg.NodeName}
		if n.cfg.ClusterName != "" {
			a["k8s.cluster.name"] = n.cfg.ClusterName
		}
	}
	a["host.name"] = n.cfg.NodeName // the node's name, whatever the pod's hostname is
	n.mu.Lock()
	if len(n.attrs) >= attrCacheSize {
		n.attrs = map[string]cachedAttrs{}
	}
	n.attrs[uid] = cachedAttrs{a: a, at: time.Now()}
	n.mu.Unlock()
	return a
}

// tailLogs follows /var/log/pods/<ns>_<pod>_<uid>/<container>/<n>.log. Each CRI line
// ("<time> <stream> <P|F> <text>") becomes a log record on the resource of its pod and container.
// Multiline joining is not offered: every line carries the CRI prefix.
func (n *nodeAgent) tailLogs(ctx context.Context, stateDir string) {
	dir := filepath.Join(stateDir, "k8s")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		slog.Warn("k8s pod logs disabled", "error", err)
		return
	}
	ps := &podLogSink{ctx: ctx, base: n.out, dir: filepath.Clean(n.cfg.PodLogDir), attrs: n.podAttrs}
	spec := logs.TailSpec{Path: filepath.Join(n.cfg.PodLogDir, "*", "*", "*.log"), MaxFiles: 5000}
	t, err := logs.NewTailer([]logs.TailSpec{spec}, logs.LoadState(dir), ps)
	if err != nil {
		slog.Warn("k8s pod logs disabled", "error", err)
		return
	}
	tk := time.NewTicker(logTailEvery)
	defer tk.Stop()
	for {
		t.Poll(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// podLogSink rewrites the tailer's records: parse the CRI line, attach the pod's resource.
type podLogSink struct {
	ctx   context.Context
	base  sink.Sink
	dir   string
	attrs func(ctx context.Context, uid, ns, name string) map[string]string
}

func (s *podLogSink) Gauge(name, unit string, v float64, a map[string]string, at time.Time) {
	s.base.Gauge(name, unit, v, a, at)
}

func (s *podLogSink) Sum(name, unit string, v float64, a map[string]string, at time.Time) {
	s.base.Sum(name, unit, v, a, at)
}

// ParsePodLogPath splits <dir>/<ns>_<pod>_<uid>/<container>/<n>.log.
func ParsePodLogPath(dir, path string) (ns, pod, uid, container string, ok bool) {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 3 || !strings.HasSuffix(parts[2], ".log") {
		return
	}
	seg := strings.Split(parts[0], "_")
	if len(seg) != 3 {
		return
	}
	return seg[0], seg[1], seg[2], parts[1], true
}

// ParseCRI splits one CRI log line. partial is true for a "P" (continued) line.
func ParseCRI(line string) (at time.Time, stream, text string, partial, ok bool) {
	f := strings.SplitN(line, " ", 4)
	if len(f) < 3 {
		return
	}
	t, err := time.Parse(time.RFC3339Nano, f[0])
	if err != nil || (f[1] != "stdout" && f[1] != "stderr") {
		return
	}
	if len(f) == 4 {
		text = f[3]
	}
	return t, f[1], text, f[2] == "P", true
}

func (s *podLogSink) Log(_, body string, a map[string]string, at time.Time) {
	ns, pod, uid, ctr, ok := ParsePodLogPath(s.dir, a["log.file.path"])
	if !ok {
		s.base.Log(logs.Severity(body), body, a, at)
		return
	}
	t, stream, text, _, ok := ParseCRI(body)
	if !ok {
		t, stream, text = at, "", body
	}
	res := sink.With(s.attrs(s.ctx, uid, ns, pod), "k8s.container.name", ctr)
	attrs := sink.Res(res)
	attrs["log.file.path"] = a["log.file.path"]
	if stream != "" {
		attrs["log.iostream"] = stream
	}
	s.base.Log(logs.Severity(text), text, attrs, t)
}
