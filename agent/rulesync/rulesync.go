// Package rulesync is the agent module `prometheus_rules` (CFT-A09, Alloy mimir.rules.kubernetes
// parity): it lists PrometheusRule custom resources (monitoring.coreos.com/v1) in the agent's
// cluster and keeps one Watchtower rule group per CRD group, named `k8s.<ns>.<name>.<group>`.
// PUT /v1/projects/{prj}/rule-groups/{name} is an upsert that keeps rule ids and alert state, so
// a changed CRD updates in place; a group whose CRD or group vanished is deleted. The API key
// (needs alert-rule write) should be a secret reference such as `${file:/var/run/wt/rules-key}`;
// remote config can only switch the module on or off. `alertmanager_configs: true` also syncs
// AlertmanagerConfig CRDs (see am.go).
package rulesync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// Config of the module.
type Config struct {
	APIURL     string   `json:"api_url"`
	Project    string   `json:"project"`
	APIKey     string   `json:"api_key"`
	Namespaces []string `json:"namespaces"` // empty: all
	Selector   string   `json:"selector"`   // label selector on the PrometheusRule objects
	Interval   string   `json:"interval"`   // default 60s
	// AlertmanagerConfigs also syncs AlertmanagerConfig CRDs; this owns the routing tree (am.go).
	AlertmanagerConfigs bool `json:"alertmanager_configs"`
}

// Prefix marks groups this module owns; nothing else is ever deleted.
const Prefix = "k8s."

type crdList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Groups []map[string]any `json:"groups"`
		} `json:"spec"`
	} `json:"items"`
}

// Desired turns a PrometheusRule list into group name -> body. Groups whose name would exceed
// the API's 100 characters are skipped.
func Desired(raw []byte) (map[string]map[string]any, error) {
	var l crdList
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, errors.New("malformed PrometheusRule list")
	}
	out := map[string]map[string]any{}
	for _, it := range l.Items {
		for _, g := range it.Spec.Groups {
			gn, _ := g["name"].(string)
			name := Prefix + it.Metadata.Namespace + "." + it.Metadata.Name + "." + gn
			if gn == "" || len(name) > 100 || strings.Contains(name, "/") {
				slog.Warn("prometheus_rules: group skipped (name empty, too long or has /)", "crd", it.Metadata.Namespace+"/"+it.Metadata.Name)
				continue
			}
			body := map[string]any{}
			for k, v := range g {
				body[k] = v
			}
			body["name"] = name
			out[name] = body
		}
	}
	return out, nil
}

type syncer struct {
	list   func(ctx context.Context) ([]byte, error)
	want   func(ctx context.Context) (map[string]map[string]any, error) // set: used instead of list + Desired
	listAM func(ctx context.Context) ([]byte, error)                    // nil: AlertmanagerConfigs off
	amHash [32]byte
	do     func(ctx context.Context, method, rel string, body any) error
	synced map[string][32]byte // group -> hash of the body last applied
}

// once applies changed groups and deletes vanished ones.
func (s *syncer) once(ctx context.Context) error {
	want, err := s.desired(ctx)
	if err != nil {
		return err
	}
	for name, body := range want {
		b, _ := json.Marshal(body)
		h := sha256.Sum256(b)
		if old, ok := s.synced[name]; ok && old == h {
			continue
		}
		if err := s.do(ctx, http.MethodPut, "rule-groups/"+url.PathEscape(name), body); err != nil {
			slog.Warn("prometheus_rules: group not applied", "group", name, "error", err)
			continue
		}
		s.synced[name] = h
	}
	// shortcut: only groups applied by this process are deleted, so a CRD removed while the agent
	// was down leaves its group behind; list rule groups by prefix once the API offers a list.
	for name := range s.synced {
		if _, ok := want[name]; ok {
			continue
		}
		if err := s.do(ctx, http.MethodDelete, "rule-groups/"+url.PathEscape(name), nil); err != nil {
			slog.Warn("prometheus_rules: group not deleted", "group", name, "error", err)
			continue
		}
		delete(s.synced, name)
	}
	return s.alertmanager(ctx)
}

func (s *syncer) desired(ctx context.Context) (map[string]map[string]any, error) {
	if s.want != nil {
		return s.want(ctx)
	}
	raw, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	return Desired(raw)
}

func (s *syncer) alertmanager(ctx context.Context) error {
	if s.listAM == nil {
		return nil
	}
	raw, err := s.listAM(ctx)
	if err != nil {
		return err
	}
	cfg, err := MergeAlertmanager(raw)
	if err != nil {
		return err
	}
	h := sha256.Sum256(cfg)
	if h == s.amHash {
		return nil
	}
	if err := s.do(ctx, http.MethodPost, "routing:import-alertmanager?apply=true&replace=true&allow_disabled_receivers=true", json.RawMessage(cfg)); err != nil {
		return fmt.Errorf("alertmanager configs not applied: %w", err)
	}
	s.amHash = h
	return nil
}

// lister lists one monitoring.coreos.com resource (all namespaces or the configured ones) as
// one {"items": [...]} document.
func lister(cs kubernetes.Interface, c Config, version, resource string) func(ctx context.Context) ([]byte, error) {
	base := "/apis/monitoring.coreos.com/" + version
	paths := []string{base + "/" + resource}
	if len(c.Namespaces) > 0 {
		paths = paths[:0]
		for _, ns := range c.Namespaces {
			paths = append(paths, base+"/namespaces/"+url.PathEscape(ns)+"/"+resource)
		}
	}
	return func(ctx context.Context) ([]byte, error) {
		var all struct {
			Items []json.RawMessage `json:"items"`
		}
		for _, p := range paths {
			req := cs.CoreV1().RESTClient().Get().AbsPath(p)
			if c.Selector != "" {
				req = req.Param("labelSelector", c.Selector)
			}
			b, err := req.DoRaw(ctx)
			if k8serrors.IsForbidden(err) {
				return nil, fmt.Errorf("list %s: forbidden: the agent's ClusterRole needs list on monitoring.coreos.com (shipped in the agent manifests)", resource)
			}
			if err != nil {
				return nil, fmt.Errorf("list %s: %w", resource, err)
			}
			var l struct {
				Items []json.RawMessage `json:"items"`
			}
			if json.Unmarshal(b, &l) != nil {
				return nil, fmt.Errorf("malformed %s list", resource)
			}
			all.Items = append(all.Items, l.Items...)
		}
		return json.Marshal(all)
	}
}

// Run syncs until ctx ends.
func Run(ctx context.Context, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("prometheus_rules: %w", err)
	}
	every := time.Minute
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		if err != nil || d < 10*time.Second {
			return errors.New("prometheus_rules: interval must be a duration of at least 10s")
		}
		every = d
	}
	api, err := ascode.New(c.APIURL, c.APIKey, c.Project, netguard.Guarded("agent", 30*time.Second))
	if err != nil {
		return fmt.Errorf("prometheus_rules: %w", err)
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("prometheus_rules: not running in a Kubernetes cluster")
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("prometheus_rules: %w", err)
	}
	s := &syncer{
		list: lister(cs, c, "v1", "prometheusrules"),
		do: func(ctx context.Context, method, rel string, body any) error {
			return api.Do(ctx, method, rel, nil, body, nil)
		},
		synced: map[string][32]byte{},
	}
	if c.AlertmanagerConfigs {
		s.listAM = lister(cs, c, "v1alpha1", "alertmanagerconfigs")
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.once(ctx); err != nil {
			slog.Warn("prometheus_rules: sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
