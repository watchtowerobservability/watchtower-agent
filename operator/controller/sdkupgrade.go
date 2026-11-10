package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Remote SDK upgrades (Kubernetes side). The operator pulls the desired auto-instrumentation
// version per language and the pending targets from the fleet channel on the edge (WT_FLEET_ENDPOINT
// with a WT_FLEET_TOKEN holding an `agent:fleet` key), so the webhook injects the new init-container
// image, then rolls each target's workloads by stamping the pod template. Progress is reported per
// target: applying, then done once the rollout is complete (updated, available, observed) or failed
// with the reason (ProgressDeadlineExceeded, or no completion within rolloutTimeout).

// SDKUpgradeAnnotation + "-" + language on a pod template records the version the workload was last
// rolled to; it also forces the new ReplicaSet, so pods are re-admitted by the webhook.
const SDKUpgradeAnnotation = "watchtower.dev/sdk-upgrade"

var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

var (
	verMu   sync.RWMutex
	autoVer = map[string]string{}
)

// autoVersion is the remotely desired version of a language's injection image, or "".
func autoVersion(lang string) string {
	verMu.RLock()
	defer verMu.RUnlock()
	return autoVer[lang]
}

func setAutoVersions(m map[string]string) {
	verMu.Lock()
	defer verMu.Unlock()
	autoVer = m
}

// SDKTarget is one service to move to Version.
type SDKTarget struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Language string `json:"language"`
	Version  string `json:"version"`
}

// SDKClient talks to the edge's `/v1/sdk-upgrades` routes.
type SDKClient struct {
	Base, Token string
	HTTP        *http.Client
}

func (c *SDKClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	return c.HTTP.Do(req)
}

// Pending returns the targets to apply and the version desired per language.
func (c *SDKClient) Pending(ctx context.Context) ([]SDKTarget, map[string]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/sdk-upgrades?"+url.Values{"kind": {"kubernetes"}}.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("sdk upgrades: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Targets []SDKTarget `json:"targets"`
		Desired []struct {
			Language string `json:"language"`
			Version  string `json:"version"`
		} `json:"desired"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, nil, err
	}
	want := map[string]string{}
	for _, d := range out.Desired {
		if versionRe.MatchString(d.Version) {
			want[d.Language] = d.Version
		}
	}
	return out.Targets, want, nil
}

// Report records one target's progress.
func (c *SDKClient) Report(ctx context.Context, id, status, errMsg string) error {
	body := map[string]any{"kind": "kubernetes", "id": id, "status": status}
	if errMsg != "" {
		body["error"] = errMsg
	}
	b, _ := json.Marshal(body)
	resp, err := c.do(ctx, http.MethodPost, "/v1/sdk-upgrades/report", b)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sdk upgrade report: HTTP %d", resp.StatusCode)
	}
	return nil
}

// rolloutTimeout bounds a rollout that has no progress deadline of its own (StatefulSet, DaemonSet).
const rolloutTimeout = 15 * time.Minute

type workload struct{ kind, ns, name string }

type tracked struct {
	refs    []workload
	started time.Time
}

// SDKUpgrader applies remote upgrades. SyncDesired runs on every replica (each one's webhook
// injects); Reconcile only on the leader.
type SDKUpgrader struct {
	KC     kubernetes.Interface
	Client *SDKClient
	Now    func() time.Time

	seen    map[string]bool     // targets reported as applying; rolled on the next pass
	rolling map[string]*tracked // targets whose workloads were stamped; watched until complete
}

func (u *SDKUpgrader) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

// SyncDesired makes the webhook of this replica inject the desired versions.
func (u *SDKUpgrader) SyncDesired(ctx context.Context) error {
	_, want, err := u.Client.Pending(ctx)
	if err != nil {
		return err
	}
	setAutoVersions(want)
	return nil
}

// Reconcile advances each pending target: applying, then stamp the workloads (one pass later, so
// the other replicas' webhooks have synced the new image), then watch the rollouts until every
// workload is updated and available (done) or one fails (failed with the reason). A new leader
// starts over from "applying"; stamping is idempotent, so nothing restarts twice.
func (u *SDKUpgrader) Reconcile(ctx context.Context) error {
	ts, want, err := u.Client.Pending(ctx)
	if err != nil {
		return err
	}
	setAutoVersions(want)
	if u.seen == nil {
		u.seen, u.rolling = map[string]bool{}, map[string]*tracked{}
	}
	for _, t := range ts {
		if !versionRe.MatchString(t.Version) || autoLangs[t.Language].env == nil {
			_ = u.Client.Report(ctx, t.ID, "failed", "unsupported language or version")
			continue
		}
		var status, msg string
		switch tr := u.rolling[t.ID]; {
		case tr != nil:
			status, msg = u.check(ctx, tr)
		case !u.seen[t.ID]:
			if err := u.Client.Report(ctx, t.ID, "applying", ""); err == nil {
				u.seen[t.ID] = true
			}
			continue
		default:
			refs, err := u.roll(ctx, t)
			switch {
			case err != nil:
				status, msg = "failed", err.Error()
			case len(refs) == 0:
				status, msg = "failed", "no workload named "+t.Service+" opted into "+t.Language+" injection"
			default:
				u.rolling[t.ID] = &tracked{refs: refs, started: u.now()}
			}
		}
		if status == "" {
			continue // still rolling
		}
		if err := u.Client.Report(ctx, t.ID, status, msg); err != nil {
			slog.Warn("sdk upgrade report", "target", t.ID, "error", err)
			continue
		}
		delete(u.seen, t.ID)
		delete(u.rolling, t.ID)
	}
	return nil
}

// check reports ("", "") while a rollout is under way, ("done", "") when every workload is
// complete and ("failed", reason) otherwise.
func (u *SDKUpgrader) check(ctx context.Context, tr *tracked) (string, string) {
	for _, w := range tr.refs {
		ok, reason, err := u.complete(ctx, w)
		switch {
		case err != nil:
			return "failed", fmt.Sprintf("%s %s/%s: %v", w.kind, w.ns, w.name, err)
		case reason != "":
			return "failed", fmt.Sprintf("%s %s/%s: %s", w.kind, w.ns, w.name, reason)
		case !ok:
			if u.now().Sub(tr.started) > rolloutTimeout {
				return "failed", fmt.Sprintf("%s %s/%s: rollout did not complete within %s", w.kind, w.ns, w.name, rolloutTimeout)
			}
			return "", ""
		}
	}
	return "done", ""
}

func replicas(p *int32) int32 {
	if p == nil {
		return 1
	}
	return *p
}

// complete reads one workload's rollout status: ok when the new revision is observed, fully
// updated and available; a non-empty reason when the Deployment's progress deadline passed.
func (u *SDKUpgrader) complete(ctx context.Context, w workload) (ok bool, reason string, err error) {
	switch w.kind {
	case "deployment":
		d, err := u.KC.AppsV1().Deployments(w.ns).Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return false, "", err
		}
		for _, c := range d.Status.Conditions {
			if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse && c.Reason == "ProgressDeadlineExceeded" {
				return false, "ProgressDeadlineExceeded: " + c.Message, nil
			}
		}
		want := replicas(d.Spec.Replicas)
		return d.Status.ObservedGeneration >= d.Generation && d.Status.UpdatedReplicas == want &&
			d.Status.Replicas == want && d.Status.AvailableReplicas >= want, "", nil
	case "statefulset":
		s, err := u.KC.AppsV1().StatefulSets(w.ns).Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return false, "", err
		}
		want := replicas(s.Spec.Replicas)
		return s.Status.ObservedGeneration >= s.Generation && s.Status.UpdatedReplicas == want &&
			s.Status.ReadyReplicas == want && s.Status.UpdateRevision == s.Status.CurrentRevision, "", nil
	default:
		d, err := u.KC.AppsV1().DaemonSets(w.ns).Get(ctx, w.name, metav1.GetOptions{})
		if err != nil {
			return false, "", err
		}
		want := d.Status.DesiredNumberScheduled
		return d.Status.ObservedGeneration >= d.Generation && d.Status.UpdatedNumberScheduled == want &&
			d.Status.NumberAvailable == want, "", nil
	}
}

// matchesService: the workload is named for the service or labelled with it.
func matchesService(name string, labels map[string]string, svc string) bool {
	return name == svc || labels["app.kubernetes.io/name"] == svc || labels["app"] == svc
}

// patchFor stamps the template; nil when it already carries the version (nothing to roll).
func (u *SDKUpgrader) patchFor(tmpl corev1.PodTemplateSpec, ns, name string, labels map[string]string, t SDKTarget) []byte {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: tmpl.Labels, Annotations: tmpl.Annotations}}
	key := SDKUpgradeAnnotation + "-" + t.Language
	if !matchesService(name, labels, t.Service) || !wantLang(pod, t.Language) || tmpl.Annotations[key] == t.Version {
		return nil
	}
	b, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{
		key: t.Version, "kubectl.kubernetes.io/restartedAt": u.now().UTC().Format(time.RFC3339),
	}}}}})
	return b
}

// roll patches every matching Deployment, StatefulSet and DaemonSet that opted into the language
// and returns the workloads to watch (including ones already on the version).
func (u *SDKUpgrader) roll(ctx context.Context, t SDKTarget) ([]workload, error) {
	var refs []workload
	pt := types.StrategicMergePatchType
	patch := func(kind, ns, name string, tmpl corev1.PodTemplateSpec, labels map[string]string, do func([]byte) error) error {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: tmpl.Labels, Annotations: tmpl.Annotations}}
		if !matchesService(name, labels, t.Service) || !wantLang(pod, t.Language) {
			return nil
		}
		refs = append(refs, workload{kind, ns, name})
		if b := u.patchFor(tmpl, ns, name, labels, t); b != nil {
			if err := do(b); err != nil {
				return fmt.Errorf("patch %s %s/%s: %w", kind, ns, name, err)
			}
		}
		return nil
	}
	ds, err := u.KC.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for _, d := range ds.Items {
		if err := patch("deployment", d.Namespace, d.Name, d.Spec.Template, d.Labels, func(b []byte) error {
			_, e := u.KC.AppsV1().Deployments(d.Namespace).Patch(ctx, d.Name, pt, b, metav1.PatchOptions{})
			return e
		}); err != nil {
			return nil, err
		}
	}
	ss, err := u.KC.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for _, s := range ss.Items {
		if err := patch("statefulset", s.Namespace, s.Name, s.Spec.Template, s.Labels, func(b []byte) error {
			_, e := u.KC.AppsV1().StatefulSets(s.Namespace).Patch(ctx, s.Name, pt, b, metav1.PatchOptions{})
			return e
		}); err != nil {
			return nil, err
		}
	}
	dss, err := u.KC.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for _, d := range dss.Items {
		if err := patch("daemonset", d.Namespace, d.Name, d.Spec.Template, d.Labels, func(b []byte) error {
			_, e := u.KC.AppsV1().DaemonSets(d.Namespace).Patch(ctx, d.Name, pt, b, metav1.PatchOptions{})
			return e
		}); err != nil {
			return nil, err
		}
	}
	return refs, nil
}
