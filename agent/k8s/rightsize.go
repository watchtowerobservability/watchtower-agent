package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// Rightsizing (INF-005, Datadog Kubernetes Autoscaling / VPA parity): the opt-in `k8s_rightsize`
// module reads the project's recommendations (GET /v1/projects/{prj}/k8s-rightsizing) and
// patches container requests of the workloads that opted in with the annotation
//
//	watchtower.dev/rightsize: Auto | TriggerRollout | Disabled   (absent = Disabled)
//
// TriggerRollout patches the pod template at once (the controller rolls the pods out). Auto
// waits until the owner rolls the workload out anyway (a new generation not yet observed, or
// pods still being updated) and joins that rollout, so Watchtower never restarts pods on its own.
// Every patch is bounded (at most halve or double per step, never below 10m CPU / 32Mi), needs
// medium or high confidence, waits a cooldown per workload, and is audited as a Kubernetes Event
// on the workload and an INFO log record `k8s.rightsize.applied` exported to Watchtower.
const (
	AnnRightsize   = AnnPrefix + "rightsize"
	annRightsizeAt = AnnPrefix + "rightsized-at"
	minCPUMilli    = 10
	minMemMi       = 32
)

// Recommendation is the part of the API's K8sCostRecommendation the module uses.
type Recommendation struct {
	Cluster     string `json:"cluster"`
	Namespace   string `json:"namespace"`
	Workload    string `json:"workload"` // "Kind/name", or a bare name for a Deployment
	Confidence  string `json:"confidence"`
	Current     Res    `json:"current"`
	Recommended Res    `json:"recommended"`
}

// Res is requests per pod.
type Res struct {
	CPUCores float64 `json:"cpu_cores"`
	MemGiB   float64 `json:"mem_gib"`
}

// RightsizeConfig is the module config (local file only; it holds the API key reference).
type RightsizeConfig struct {
	APIURL    string  `json:"api_url"`
	Project   string  `json:"project"`
	APIKey    string  `json:"api_key"`
	Cluster   string  `json:"cluster"`   // k8s.cluster.name the recommendations carry
	Interval  string  `json:"interval"`  // default 10m
	Cooldown  string  `json:"cooldown"`  // default 24h between patches of one workload
	Tolerance float64 `json:"tolerance"` // default 0.1: smaller relative changes are skipped
	DryRun    bool    `json:"dry_run"`   // audit what would change, patch nothing
}

// workloadObj is the slice of a Deployment, StatefulSet or DaemonSet the rightsizer reads.
type workloadObj struct {
	Kind, Namespace, Name string
	Annotations           map[string]string
	Containers            []corev1.Container
	RollingOut            bool
}

// Rightsizer applies recommendations to one cluster.
type Rightsizer struct {
	Cfg   RightsizeConfig
	Fetch func(ctx context.Context) ([]Recommendation, error)
	Get   func(ctx context.Context, kind, ns, name string) (*workloadObj, error)
	Patch func(ctx context.Context, kind, ns, name string, patch []byte) error
	Event func(ctx context.Context, w *workloadObj, msg string)
	Out   sink.Sink
	Now   func() time.Time
}

// Decision is what one pass did for one workload (tests and the audit record use it).
type Decision struct {
	Workload, Namespace, Strategy, Action string
	Patch                                 []byte
}

func splitWorkload(w string) (string, string) {
	if k, n, ok := strings.Cut(w, "/"); ok {
		return strings.ToLower(k), n
	}
	return "deployment", w
}

// Once runs one pass and returns a decision for every recommendation of this cluster.
func (r *Rightsizer) Once(ctx context.Context) ([]Decision, error) {
	recs, err := r.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	cool := parseDurDefault(r.Cfg.Cooldown, 24*time.Hour)
	tol := r.Cfg.Tolerance
	if tol <= 0 {
		tol = 0.1
	}
	var out []Decision
	for _, rec := range recs {
		if r.Cfg.Cluster != "" && rec.Cluster != r.Cfg.Cluster {
			continue
		}
		kind, name := splitWorkload(rec.Workload)
		d := Decision{Workload: rec.Workload, Namespace: rec.Namespace}
		w, err := r.Get(ctx, kind, rec.Namespace, name)
		if err != nil {
			d.Action = "skipped: " + err.Error()
			out = append(out, d)
			continue
		}
		d.Strategy = w.Annotations[AnnRightsize]
		d.Action, d.Patch = r.decide(w, rec, cool, tol)
		if d.Patch != nil && !r.Cfg.DryRun {
			if err := r.Patch(ctx, kind, w.Namespace, w.Name, d.Patch); err != nil {
				d.Action = "patch failed: " + err.Error()
				d.Patch = nil
			}
		}
		if d.Patch != nil {
			msg := fmt.Sprintf("Watchtower rightsizing (%s, %s confidence): requests to %.3f cores / %.2f GiB per pod",
				d.Strategy, rec.Confidence, rec.Recommended.CPUCores, rec.Recommended.MemGiB)
			if r.Cfg.DryRun {
				msg = "dry run: " + msg
			}
			if r.Event != nil {
				r.Event(ctx, w, msg)
			}
			if r.Out != nil {
				r.Out.Log("INFO", msg, map[string]string{"event.name": "k8s.rightsize.applied", "k8s.namespace.name": w.Namespace,
					"k8s.workload": kind + "/" + w.Name, "rightsize.strategy": d.Strategy, "rightsize.patch": string(d.Patch)}, r.Now())
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// decide returns the action text and the strategic-merge patch (nil when nothing is applied).
func (r *Rightsizer) decide(w *workloadObj, rec Recommendation, cool time.Duration, tol float64) (string, []byte) {
	switch w.Annotations[AnnRightsize] {
	case "Auto":
		if !w.RollingOut {
			return "waiting for the owner's next rollout", nil
		}
	case "TriggerRollout":
	default:
		return "disabled", nil
	}
	if rec.Confidence != "high" && rec.Confidence != "medium" {
		return "skipped: low confidence", nil
	}
	if at, err := time.Parse(time.RFC3339, w.Annotations[annRightsizeAt]); err == nil && r.Now().Sub(at) < cool {
		return "skipped: cooldown", nil
	}
	if rel(rec.Current.CPUCores, rec.Recommended.CPUCores) < tol && rel(rec.Current.MemGiB, rec.Recommended.MemGiB) < tol {
		return "skipped: within tolerance", nil
	}
	p, err := requestsPatch(w, rec, r.Now())
	if err != nil {
		return "skipped: " + err.Error(), nil
	}
	return "patched", p
}

func rel(cur, rec float64) float64 {
	if cur <= 0 {
		return math.Inf(1)
	}
	return math.Abs(rec-cur) / cur
}

// requestsPatch scales each container's requests by recommended/current (the recommendation
// is per pod), bounded to [0.5, 2] per step and floored.
func requestsPatch(w *workloadObj, rec Recommendation, now time.Time) ([]byte, error) {
	if len(w.Containers) == 0 {
		return nil, errors.New("no containers")
	}
	var curCPU, curMem float64
	for _, c := range w.Containers {
		curCPU += c.Resources.Requests.Cpu().AsApproximateFloat64()
		curMem += c.Resources.Requests.Memory().AsApproximateFloat64() / (1 << 30)
	}
	factor := func(cur, want float64) float64 {
		if cur <= 0 {
			return 0 // no requests set: each container gets an equal share below
		}
		return math.Min(2, math.Max(0.5, want/cur))
	}
	fc, fm := factor(curCPU, rec.Recommended.CPUCores), factor(curMem, rec.Recommended.MemGiB)
	type req struct {
		CPU    string `json:"cpu"`
		Memory string `json:"memory"`
	}
	type ctr struct {
		Name      string `json:"name"`
		Resources struct {
			Requests req `json:"requests"`
		} `json:"resources"`
	}
	n := float64(len(w.Containers))
	cs := make([]ctr, 0, len(w.Containers))
	for _, c := range w.Containers {
		cpu := c.Resources.Requests.Cpu().AsApproximateFloat64() * fc
		mem := c.Resources.Requests.Memory().AsApproximateFloat64() / (1 << 30) * fm
		if fc == 0 {
			cpu = rec.Recommended.CPUCores / n
		}
		if fm == 0 {
			mem = rec.Recommended.MemGiB / n
		}
		var x ctr
		x.Name = c.Name
		x.Resources.Requests = req{
			CPU:    resource.NewMilliQuantity(int64(math.Max(minCPUMilli, math.Ceil(cpu*1000))), resource.DecimalSI).String(),
			Memory: resource.NewQuantity(int64(math.Max(minMemMi, math.Ceil(mem*1024)))<<20, resource.BinarySI).String(),
		}
		cs = append(cs, x)
	}
	body := map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{annRightsizeAt: now.UTC().Format(time.RFC3339)}},
		"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"containers": cs}}},
	}
	return json.Marshal(body)
}

func parseDurDefault(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// kubeWorkloads binds Get, Patch and Event to the API server.
func kubeWorkloads(cs kubernetes.Interface, r *Rightsizer) {
	r.Get = func(ctx context.Context, kind, ns, name string) (*workloadObj, error) {
		apps := cs.AppsV1()
		switch kind {
		case "deployment":
			d, err := apps.Deployments(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			out := d.Status.ObservedGeneration < d.Generation || (d.Spec.Replicas != nil && d.Status.UpdatedReplicas < *d.Spec.Replicas)
			return &workloadObj{Kind: kind, Namespace: ns, Name: name, Annotations: d.Annotations, Containers: d.Spec.Template.Spec.Containers, RollingOut: out}, nil
		case "statefulset":
			s, err := apps.StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			out := s.Status.ObservedGeneration < s.Generation || s.Status.UpdateRevision != s.Status.CurrentRevision
			return &workloadObj{Kind: kind, Namespace: ns, Name: name, Annotations: s.Annotations, Containers: s.Spec.Template.Spec.Containers, RollingOut: out}, nil
		case "daemonset":
			d, err := apps.DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			out := d.Status.ObservedGeneration < d.Generation || d.Status.UpdatedNumberScheduled < d.Status.DesiredNumberScheduled
			return &workloadObj{Kind: kind, Namespace: ns, Name: name, Annotations: d.Annotations, Containers: d.Spec.Template.Spec.Containers, RollingOut: out}, nil
		}
		return nil, fmt.Errorf("kind %s is not rightsized", kind)
	}
	r.Patch = func(ctx context.Context, kind, ns, name string, p []byte) error {
		apps := cs.AppsV1()
		var err error
		switch kind {
		case "deployment":
			_, err = apps.Deployments(ns).Patch(ctx, name, types.StrategicMergePatchType, p, metav1.PatchOptions{FieldManager: "watchtower-rightsize"})
		case "statefulset":
			_, err = apps.StatefulSets(ns).Patch(ctx, name, types.StrategicMergePatchType, p, metav1.PatchOptions{FieldManager: "watchtower-rightsize"})
		case "daemonset":
			_, err = apps.DaemonSets(ns).Patch(ctx, name, types.StrategicMergePatchType, p, metav1.PatchOptions{FieldManager: "watchtower-rightsize"})
		}
		return err
	}
	r.Event = func(ctx context.Context, w *workloadObj, msg string) {
		kinds := map[string]string{"deployment": "Deployment", "statefulset": "StatefulSet", "daemonset": "DaemonSet"}
		ev := &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{GenerateName: w.Name + "-rightsize-", Namespace: w.Namespace},
			InvolvedObject: corev1.ObjectReference{APIVersion: "apps/v1", Kind: kinds[w.Kind], Namespace: w.Namespace, Name: w.Name},
			Reason:         "WatchtowerRightsized", Message: msg, Type: corev1.EventTypeNormal,
			Source:         corev1.EventSource{Component: "watchtower-agent"},
			FirstTimestamp: metav1.NewTime(r.Now()), LastTimestamp: metav1.NewTime(r.Now()), Count: 1,
		}
		if _, err := cs.CoreV1().Events(w.Namespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
			slog.Warn("k8s_rightsize: audit event not written", "workload", w.Kind+"/"+w.Name, "error", err)
		}
	}
}

// RunRightsize runs the module on the elected replica until ctx ends.
func RunRightsize(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c RightsizeConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("k8s_rightsize: %w", err)
	}
	api, err := ascode.New(c.APIURL, c.APIKey, c.Project, netguard.Guarded("agent", 30*time.Second))
	if err != nil {
		return fmt.Errorf("k8s_rightsize: %w", err)
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("k8s_rightsize: not running in a Kubernetes cluster")
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	r := &Rightsizer{Cfg: c, Out: out, Now: time.Now, Fetch: func(ctx context.Context) ([]Recommendation, error) {
		var page struct {
			Data []Recommendation `json:"data"`
		}
		err := api.Do(ctx, http.MethodGet, "k8s-rightsizing", nil, nil, &page)
		return page.Data, err
	}}
	kubeWorkloads(cs, r)
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return errors.New("k8s_rightsize: the pod's namespace is unknown")
	}
	ns := strings.TrimSpace(string(b))
	host, _ := os.Hostname() // the pod name
	every := parseDurDefault(c.Interval, 10*time.Minute)
	return RunElected(ctx, cs, ns, "wt-k8s-rightsize", host, DefaultTiming, func(lctx context.Context) error {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			if _, err := r.Once(lctx); err != nil {
				slog.Warn("k8s_rightsize: pass failed", "error", err)
			}
			select {
			case <-lctx.Done():
				return nil
			case <-t.C:
			}
		}
	})
}
