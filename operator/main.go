// Command operator reconciles one WatchtowerCluster custom resource (PLT-033).
//
// Environment: WT_NAMESPACE (default: the pod's namespace file), WT_CLUSTER (the CR name, also the
// Helm release name), WT_API_URL (wt-api base URL for /internal/lag) and WT_INTERNAL_TOKEN.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	k8sagent "github.com/watchtowerobservability/watchtower-agent/agent/k8s"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
	v1 "github.com/watchtowerobservability/watchtower-agent/operator/api/v1"
	"github.com/watchtowerobservability/watchtower-agent/operator/controller"
)

var gvr = schema.GroupVersionResource{Group: v1.Group, Version: v1.Version, Resource: v1.Resource}

var agentGVR = schema.GroupVersionResource{Group: v1.Group, Version: v1.Version, Resource: v1.AgentResource}

type crStore struct {
	dyn      dynamic.ResourceInterface
	name, ns string
}

func (s crStore) Get(ctx context.Context) (*v1.WatchtowerCluster, error) {
	u, err := s.dyn.Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	cr := &v1.WatchtowerCluster{Name: s.name, Namespace: s.ns}
	if sp, ok, _ := unstructured.NestedMap(u.Object, "spec"); ok {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(sp, &cr.Spec); err != nil {
			return nil, fmt.Errorf("decode spec: %w", err)
		}
	}
	if st, ok, _ := unstructured.NestedMap(u.Object, "status"); ok {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(st, &cr.Status); err != nil {
			return nil, fmt.Errorf("decode status: %w", err)
		}
	}
	return cr, nil
}

func (s crStore) UpdateStatus(ctx context.Context, st v1.Status) error {
	u, err := s.dyn.Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&st)
	if err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(u.Object, m, "status"); err != nil {
		return err
	}
	_, err = s.dyn.UpdateStatus(ctx, u, metav1.UpdateOptions{})
	return err
}

// lagFunc reads {"lag": n} from wt-api's internal listener.
func lagFunc(base, token string) func(context.Context) (int64, error) {
	hc := netguard.NewClient(netguard.FromEnv("operator"))
	hc.Timeout = 10 * time.Second
	return func(ctx context.Context) (int64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/internal/lag", nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-WT-Internal-Token", token)
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("lag endpoint: HTTP %d", resp.StatusCode)
		}
		var out struct {
			Lag int64 `json:"lag"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return 0, err
		}
		return out.Lag, nil
	}
}

// agentStore is the WatchtowerAgent custom resource (same group and version as the cluster CR).
type agentStore struct {
	dyn      dynamic.ResourceInterface
	name, ns string
}

func (s agentStore) Get(ctx context.Context) (*v1.WatchtowerAgent, error) {
	u, err := s.dyn.Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	cr := &v1.WatchtowerAgent{Name: s.name, Namespace: s.ns}
	if sp, ok, _ := unstructured.NestedMap(u.Object, "spec"); ok {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(sp, &cr.Spec); err != nil {
			return nil, fmt.Errorf("decode spec: %w", err)
		}
	}
	if st, ok, _ := unstructured.NestedMap(u.Object, "status"); ok {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(st, &cr.Status); err != nil {
			return nil, fmt.Errorf("decode status: %w", err)
		}
	}
	return cr, nil
}

func (s agentStore) UpdateStatus(ctx context.Context, st v1.AgentStatus) error {
	u, err := s.dyn.Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&st)
	if err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(u.Object, m, "status"); err != nil {
		return err
	}
	_, err = s.dyn.UpdateStatus(ctx, u, metav1.UpdateOptions{})
	return err
}

// serveWebhook serves the pod injection webhook over TLS when WT_WEBHOOK_CERT and WT_WEBHOOK_KEY
// name the mounted serving certificate (the chart's `injection.service` points at it).
func serveWebhook(ctx context.Context) {
	cert, key := os.Getenv("WT_WEBHOOK_CERT"), os.Getenv("WT_WEBHOOK_KEY")
	if cert == "" || key == "" {
		return
	}
	port := 4318 // the agent's OTLP/HTTP port
	if p, err := strconv.Atoi(os.Getenv("WT_INJECT_PORT")); err == nil && p > 0 && p < 65536 {
		port = p
	}
	addr := os.Getenv("WT_WEBHOOK_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	mux := http.NewServeMux()
	mux.Handle("POST /mutate", controller.Mutate(port))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServeTLS(cert, key); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("webhook", "error", err)
		}
	}()
}

func namespace() string {
	if ns := os.Getenv("WT_NAMESPACE"); ns != "" {
		return ns
	}
	b, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	return string(b)
}

func run(ctx context.Context) error {
	name, ns := os.Getenv("WT_CLUSTER"), namespace()
	if name == "" || ns == "" {
		return errors.New("WT_CLUSTER and the namespace are required")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	store := crStore{dyn: dc.Resource(gvr).Namespace(ns), name: name, ns: ns}
	serveWebhook(ctx)
	// WT_AGENT_CR names the WatchtowerAgent to reconcile next to the cluster (optional).
	var agentRec *controller.AgentReconciler
	if an := os.Getenv("WT_AGENT_CR"); an != "" {
		agentRec = &controller.AgentReconciler{KC: kc, Namespace: ns,
			Store: agentStore{dyn: dc.Resource(agentGVR).Namespace(ns), name: an, ns: ns}}
	}
	rec := controller.NewReconciler(kc, store, lagFunc(os.Getenv("WT_API_URL"), os.Getenv("WT_INTERNAL_TOKEN")))
	host, _ := os.Hostname()
	return k8sagent.RunElected(ctx, kc, ns, "wt-operator-"+name, host, k8sagent.DefaultTiming, func(c context.Context) error {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			if err := rec.Reconcile(c); err != nil {
				slog.Warn("reconcile", "error", err)
			}
			if agentRec != nil {
				if err := agentRec.Reconcile(c); err != nil {
					slog.Warn("agent reconcile", "error", err)
				}
			}
			select {
			case <-c.Done():
				return nil
			case <-t.C:
			}
		}
	})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("operator", "error", err)
		os.Exit(1)
	}
}
