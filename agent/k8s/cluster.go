package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// ClusterConfig is the cluster agent's config. Only Enabled and Interval can be set remotely.
type ClusterConfig struct {
	Enabled      *bool  `json:"enabled"`
	Interval     string `json:"interval"` // state metrics, default 60s, at least 10s
	ClusterName  string `json:"cluster_name"`
	Namespace    string `json:"namespace"`  // of the Lease; default the pod's own
	LeaseName    string `json:"lease_name"` // default wt-cluster-agent
	Identity     string `json:"identity"`   // default $POD_NAME, then the hostname
	Events       *bool  `json:"events"`     // default true
	EventsPerSec int    `json:"events_per_sec"`
	// ControlPlane scrapes API server, scheduler, controller manager and etcd metrics (leader only).
	ControlPlane *ControlPlaneConfig `json:"controlplane"`

	rest *rest.Config // set by RunCluster; enables the CRD change watch
}

func (c *ClusterConfig) defaults() {
	if c.LeaseName == "" {
		c.LeaseName = "wt-cluster-agent"
	}
	if c.Namespace == "" {
		if b, err := os.ReadFile(filepath.Join(saDir, "namespace")); err == nil {
			c.Namespace = strings.TrimSpace(string(b))
		}
	}
	if c.Identity == "" {
		c.Identity = os.Getenv("POD_NAME")
	}
	if c.Identity == "" {
		c.Identity, _ = os.Hostname()
	}
	if c.EventsPerSec <= 0 {
		c.EventsPerSec = 50
	}
}

// RunCluster runs the cluster agent: wins the Lease, then (only while leading) watches the
// cluster and reports state metrics, events and spec changes. Replicas that do not hold the
// Lease stay idle.
func RunCluster(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c ClusterConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled {
		<-ctx.Done()
		return nil
	}
	c.defaults()
	if c.Namespace == "" || c.Identity == "" {
		return errors.New("k8s_cluster: lease namespace and identity are required")
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("k8s_cluster: %w", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	c.rest = rc
	out = sink.Hoist(out)
	if c.ControlPlane != nil {
		if err := c.ControlPlane.validate(); err != nil {
			return err
		}
	}
	return RunElected(ctx, cs, c.Namespace, c.LeaseName, c.Identity, DefaultTiming, func(ctx context.Context) error {
		return leadWithRetry(ctx, func(ctx context.Context) error { return runLeader(ctx, cs, c, out) })
	})
}

// Cache sync can fail on a slow or partly forbidden cluster. Leading retries a few times with
// backoff; if it still fails, the error goes to RunElected, which releases the Lease.
var (
	leadAttempts = 5
	leadBackoff  = 2 * time.Second
)

func leadWithRetry(ctx context.Context, run func(context.Context) error) error {
	var err error
	for i := 0; i < leadAttempts; i++ {
		if err = run(ctx); err == nil || ctx.Err() != nil {
			return nil
		}
		slog.Warn("k8s cluster agent not ready", "attempt", i+1, "error", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(leadBackoff << i):
		}
	}
	return err
}

type cluster struct {
	cfg     ClusterConfig
	out     sink.Sink
	lim     *limiter
	seen    *eventSeen
	snapped *eventSeen // pods whose manifest was logged
	start   time.Time

	pods, nodes, namespaces, deployments, replicasets, statefulsets cache.Store
	daemonsets, jobs, cronjobs, services, ingresses, pvcs           cache.Store
	netpols                                                         cache.Store
}

// newCluster registers the informers of f (before it starts) and returns their sync checks.
func newCluster(f informers.SharedInformerFactory, cfg ClusterConfig, out sink.Sink) (*cluster, []cache.InformerSynced, error) {
	c := &cluster{cfg: cfg, out: out, lim: newLimiter(cfg.EventsPerSec), seen: newEventSeen(), snapped: newEventSeen(), start: time.Now()}
	type kind struct {
		inf   cache.SharedIndexInformer
		store *cache.Store
		diff  string // workload kind whose spec changes are logged; "" for none
	}
	core, apps, batch := f.Core().V1(), f.Apps().V1(), f.Batch().V1()
	kinds := []kind{
		{core.Pods().Informer(), &c.pods, ""},
		{core.Nodes().Informer(), &c.nodes, ""},
		{core.Namespaces().Informer(), &c.namespaces, ""},
		{apps.Deployments().Informer(), &c.deployments, "deployment"},
		{apps.ReplicaSets().Informer(), &c.replicasets, ""},
		{apps.StatefulSets().Informer(), &c.statefulsets, "statefulset"},
		{apps.DaemonSets().Informer(), &c.daemonsets, "daemonset"},
		{batch.Jobs().Informer(), &c.jobs, ""},
		{batch.CronJobs().Informer(), &c.cronjobs, "cronjob"},
		{core.Services().Informer(), &c.services, ""},
		{f.Networking().V1().Ingresses().Informer(), &c.ingresses, ""},
		{core.PersistentVolumeClaims().Informer(), &c.pvcs, ""},
		{f.Networking().V1().NetworkPolicies().Informer(), &c.netpols, "networkpolicy"},
	}
	syncs := make([]cache.InformerSynced, 0, len(kinds)+1)
	for _, k := range kinds {
		if err := k.inf.SetTransform(Trim); err != nil {
			return nil, nil, err
		}
		*k.store = k.inf.GetStore()
		if k.diff != "" {
			name := k.diff
			if _, err := k.inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
				UpdateFunc: func(oldObj, newObj any) { c.onSpecChange(name, oldObj, newObj) },
			}); err != nil {
				return nil, nil, err
			}
		}
		syncs = append(syncs, k.inf.HasSynced)
	}
	if _, err := core.Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.snapshotPod, UpdateFunc: c.onPodUpdate, DeleteFunc: c.onPodDelete,
	}); err != nil {
		return nil, nil, err
	}
	if cfg.Events == nil || *cfg.Events {
		ev := core.Events().Informer()
		if err := ev.SetTransform(Trim); err != nil {
			return nil, nil, err
		}
		if _, err := ev.AddEventHandler(c.eventHandler()); err != nil {
			return nil, nil, err
		}
		syncs = append(syncs, ev.HasSynced)
	}
	return c, syncs, nil
}

// runLeader builds the informers, waits for them, then reports until ctx ends.
func runLeader(ctx context.Context, cs kubernetes.Interface, cfg ClusterConfig, out sink.Sink) error {
	f := informers.NewSharedInformerFactory(cs, resyncPeriod)
	c, syncs, err := newCluster(f, cfg, out)
	if err != nil {
		return err
	}
	f.Start(ctx.Done())
	sctx, cancel := context.WithTimeout(ctx, syncTimeout)
	ok := cache.WaitForCacheSync(sctx.Done(), syncs...)
	cancel()
	if !ok {
		return errors.New("caches did not sync")
	}
	if cfg.rest != nil {
		if err := c.watchCRDs(ctx, cfg.rest); err != nil {
			slog.Warn("k8s_cluster: CRD change history disabled", "err", err)
		}
	}
	iv := Duration(cfg.Interval, 60*time.Second, 10*time.Second)
	if cp := cfg.ControlPlane; cp != nil && (cp.Enabled == nil || *cp.Enabled) {
		scraper, err := NewControlPlane(*cp, apiServerURL(), cfg.ClusterName, c.controlPlaneURLs)
		if err != nil {
			return err
		}
		go runControlPlane(ctx, scraper, iv, out)
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		c.emitState(ctx, time.Now())
		select {
		case <-ctx.Done():
			f.Shutdown()
			return nil
		case <-t.C:
		}
	}
}

// lookup resolves ReplicaSet and Job owners from the informer stores (no API calls).
func (c *cluster) lookup(_ context.Context, kind, ns, name string) (*metav1.OwnerReference, bool) {
	var st cache.Store
	switch kind {
	case "ReplicaSet":
		st = c.replicasets
	case "Job":
		st = c.jobs
	default:
		return nil, false
	}
	o, ok, err := st.GetByKey(ns + "/" + name)
	if err != nil || !ok {
		return nil, false
	}
	m, err := meta.Accessor(o)
	if err != nil {
		return nil, false
	}
	ref := controllerRef(m.GetOwnerReferences())
	return ref, ref != nil
}

// apiServerURL is the in-cluster API server base URL from the standard environment.
func apiServerURL() string {
	h, p := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if h == "" || p == "" {
		return "https://kubernetes.default.svc"
	}
	return "https://" + net.JoinHostPort(h, p)
}

// controlPlaneURLs resolves a component name to its static pods from the pod cache.
func (c *cluster) controlPlaneURLs(component string) []string {
	var pods []*corev1.Pod
	for _, o := range c.pods.List() {
		if p, ok := o.(*corev1.Pod); ok {
			pods = append(pods, p)
		}
	}
	return ControlPlaneURLs(pods, component)
}
