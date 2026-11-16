package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/watchtowerobservability/watchtower-agent/agent/integrations"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// scopeEnvVar lists the namespaces of namespaced scope (comma separated). When set, the
// cluster and node modules stay off: they need cluster-wide, node and kubelet access.
const scopeEnvVar = "WT_AGENT_K8S_NAMESPACES"

func scopeEnv() string { return strings.TrimSpace(os.Getenv(scopeEnvVar)) }

// ScopedConfig is the config of the "kubernetes" module (namespaced scope). Only Enabled and
// Interval can be set remotely. Every API call is made inside one of Namespaces; nothing is ever
// listed cluster-wide and filtered afterwards, so a Role per namespace is all the RBAC it needs.
type ScopedConfig struct {
	Enabled           *bool    `json:"enabled"`
	Interval          string   `json:"interval"` // default 30s, at least 10s
	ClusterName       string   `json:"cluster_name"`
	Namespaces        []string `json:"namespaces"`         // or $WT_AGENT_K8S_NAMESPACES
	ExcludeNamespaces []string `json:"exclude_namespaces"` // removed from Namespaces
	Selector          string   `json:"selector"`           // label selector applied to pods (server side)
	MaxLogStreams     int      `json:"max_log_streams"`    // concurrent pods/log follows, default 50
	Logs              *bool    `json:"logs"`               // default true
	Events            *bool    `json:"events"`             // default true
	Metrics           *bool    `json:"metrics"`            // metrics.k8s.io PodMetrics, default true
}

// Scope resolves the namespaces to watch: the configured list (else the environment) minus the
// excluded ones, de-duplicated and sorted. An empty result is an error: namespaced mode never
// falls back to the whole cluster. The selector is validated here.
func (c *ScopedConfig) Scope() ([]string, error) {
	list := c.Namespaces
	if len(list) == 0 {
		list = strings.Split(scopeEnv(), ",")
	}
	var out []string
	for _, ns := range list {
		ns = strings.TrimSpace(ns)
		if ns != "" && !slices.Contains(c.ExcludeNamespaces, ns) && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("kubernetes: no namespaces (set kubernetes.namespaces or " + scopeEnvVar + ")")
	}
	if _, err := labels.Parse(c.Selector); err != nil {
		return nil, fmt.Errorf("kubernetes: selector: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

func on(b *bool) bool { return b == nil || *b }

// RunScoped runs the namespaced agent until ctx ends.
func RunScoped(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c ScopedConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	nss, err := c.Scope()
	if err != nil {
		return err
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("kubernetes: %w", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	slog.Info("kubernetes: namespaced scope; node, kubelet, cadvisor, control plane and cluster checks are off",
		"namespaces", nss, "selector", c.Selector)
	return runScoped(ctx, c, nss, cs, restFetch(cs), sink.Hoist(out))
}

type scoped struct {
	cfg   ScopedConfig
	nss   []string
	pods  map[string]cache.Store // by namespace
	cl    *cluster               // state metrics and event rendering
	fetch fetchFunc
	out   sink.Sink
	logs  *logStreamer
}

func runScoped(ctx context.Context, cfg ScopedConfig, nss []string, cs kubernetes.Interface, fetch fetchFunc, out sink.Sink) error {
	s := &scoped{cfg: cfg, nss: nss, pods: map[string]cache.Store{}, fetch: fetch, out: out}
	s.cl = &cluster{cfg: ClusterConfig{ClusterName: cfg.ClusterName, EventsPerSec: 50}, out: out,
		lim: newLimiter(50), seen: newEventSeen(), snapped: newEventSeen(), start: time.Now(), apiLook: NewAPILookup(cs)}
	var syncs []cache.InformerSynced
	var facs []informers.SharedInformerFactory
	for _, ns := range nss {
		pf := informers.NewSharedInformerFactoryWithOptions(cs, resyncPeriod, informers.WithNamespace(ns),
			informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = cfg.Selector }))
		inf := pf.Core().V1().Pods().Informer()
		if err := inf.SetTransform(Trim); err != nil {
			return err
		}
		s.pods[ns] = inf.GetStore()
		syncs = append(syncs, inf.HasSynced)
		facs = append(facs, pf)
		if on(cfg.Events) {
			ef := informers.NewSharedInformerFactoryWithOptions(cs, resyncPeriod, informers.WithNamespace(ns))
			ev := ef.Core().V1().Events().Informer()
			if err := ev.SetTransform(Trim); err != nil {
				return err
			}
			if _, err := ev.AddEventHandler(s.cl.eventHandler()); err != nil {
				return err
			}
			syncs = append(syncs, ev.HasSynced)
			facs = append(facs, ef)
		}
	}
	s.cl.eventFilter = s.eventInScope
	for _, f := range facs {
		f.Start(ctx.Done())
	}
	sctx, cancel := context.WithTimeout(ctx, syncTimeout)
	ok := cache.WaitForCacheSync(sctx.Done(), syncs...)
	cancel()
	if !ok {
		return errors.New("kubernetes: caches did not sync (is the Role bound in every namespace?)")
	}
	if on(cfg.Logs) {
		s.logs = newLogStreamer(cs, s, cfg.MaxLogStreams, time.Now())
		go s.logs.run(ctx)
	}
	go integrations.RunAnnotated(ctx, func() []integrations.PodCheck { return podChecks(s.podList()) }, out, 30*time.Second)
	t := time.NewTicker(Duration(cfg.Interval, 30*time.Second, 10*time.Second))
	defer t.Stop()
	for {
		s.poll(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (s *scoped) podList() []*corev1.Pod {
	var l []*corev1.Pod
	for _, ns := range s.nss {
		each(s.pods[ns], func(p *corev1.Pod) { l = append(l, p) })
	}
	return l
}

func (s *scoped) pod(ns, name string) *corev1.Pod {
	st := s.pods[ns]
	if st == nil {
		return nil
	}
	o, _, _ := st.GetByKey(ns + "/" + name)
	p, _ := o.(*corev1.Pod)
	return p
}

// eventInScope: with a selector only the events of pods that match it are reported (the Event
// carries no labels, so it is matched through its pod).
func (s *scoped) eventInScope(e *corev1.Event) bool {
	if s.cfg.Selector == "" || e.InvolvedObject.Kind != "Pod" {
		return true
	}
	return s.pod(e.InvolvedObject.Namespace, e.InvolvedObject.Name) != nil
}

func (s *scoped) poll(ctx context.Context) {
	pods := s.podList()
	t := Discover(pods)
	discovered.Store(&t)
	now := time.Now()
	s.cl.emitPodList(ctx, s.out, now, pods)
	if on(s.cfg.Metrics) {
		s.emitMetrics(ctx, now)
	}
}
