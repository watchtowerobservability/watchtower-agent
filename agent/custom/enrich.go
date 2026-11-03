package custom

// Enrich from discovery (CFT-A06, Alloy prometheus.enrich / loki.enrich parity): the `enrich`
// module keeps the targets of its sd_configs (any discovery type of the prometheus module) and
// adds chosen target labels to every metric point and log record whose match attribute equals
// a target's label (an `__address__` matches with or without its port). Local config only.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// EnrichRule joins one discovery set into the data.
type EnrichRule struct {
	SDConfigs   []SDConfig        `json:"sd_configs"`
	MatchAttr   string            `json:"match_attr"`   // e.g. host.name, net.host.ip, k8s.pod.name
	TargetLabel string            `json:"target_label"` // default __address__
	Labels      map[string]string `json:"labels"`       // target label -> attribute to set
}

// EnrichConfig is the module config.
type EnrichConfig struct {
	Rules   []EnrichRule `json:"rules"`
	Refresh string       `json:"refresh"` // default 60s
}

// Enricher is safe for concurrent use; Apply is a no-op until Run has loaded targets.
type Enricher struct {
	mu    sync.RWMutex
	rules []EnrichRule
	idx   []map[string]map[string]string // per rule: match value -> attrs to add
}

func hostOnly(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// Apply adds the joined labels to attrs (in place); existing attributes are kept.
func (e *Enricher) Apply(attrs map[string]string) {
	if e == nil {
		return
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for i, r := range e.rules {
		v, ok := attrs[r.MatchAttr]
		if !ok {
			continue
		}
		add := e.idx[i][v]
		if add == nil {
			add = e.idx[i][hostOnly(v)]
		}
		for k, val := range add {
			if _, has := attrs[k]; !has {
				attrs[k] = val
			}
		}
	}
}

// Index builds the lookup of one rule from targets.
func (r EnrichRule) Index(ts []TargetSpec) map[string]map[string]string {
	label := cmpOr(r.TargetLabel, "__address__")
	out := map[string]map[string]string{}
	for _, t := range ts {
		v := t.Labels[label]
		if label == "__address__" && v == "" {
			v = t.URL
		}
		if v == "" {
			continue
		}
		add := map[string]string{}
		for from, to := range r.Labels {
			if x := t.Labels[from]; x != "" {
				add[to] = x
			}
		}
		out[v] = add
		if label == "__address__" {
			out[hostOnly(v)] = add
		}
	}
	return out
}

// Run loads cfg and refreshes the targets until ctx ends; then Apply stops enriching.
func (e *Enricher) Run(ctx context.Context, raw json.RawMessage) error {
	var c EnrichConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("enrich: %w", err)
	}
	every := time.Minute
	if c.Refresh != "" {
		d, err := time.ParseDuration(c.Refresh)
		if err != nil || d < 10*time.Second {
			return errors.New("enrich: refresh must be at least 10s")
		}
		every = d
	}
	for i, r := range c.Rules {
		if r.MatchAttr == "" || len(r.Labels) == 0 || len(r.SDConfigs) == 0 {
			return fmt.Errorf("enrich: rule %d needs sd_configs, match_attr and labels", i)
		}
	}
	defer func() {
		e.mu.Lock()
		e.rules, e.idx = nil, nil
		e.mu.Unlock()
	}()
	hc := netguard.Guarded("agent", 30*time.Second)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		e.refresh(ctx, hc, c.Rules)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (e *Enricher) refresh(ctx context.Context, hc *http.Client, rules []EnrichRule) {
	idx := make([]map[string]map[string]string, len(rules))
	for i, r := range rules {
		var all []TargetSpec
		for _, sd := range r.SDConfigs {
			ts, err := sd.discover(ctx, hc)
			if err != nil {
				slog.Warn("enrich: discovery failed", "type", sd.Type, "error", err)
				continue
			}
			all = append(all, ts...)
		}
		idx[i] = r.Index(all)
	}
	e.mu.Lock()
	e.rules, e.idx = rules, idx
	e.mu.Unlock()
}
