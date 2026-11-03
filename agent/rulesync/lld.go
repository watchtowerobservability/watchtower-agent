package rulesync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// LLDConfig is the `lld_rules` module (INF-020, Zabbix low-level discovery trigger prototypes):
// each prototype becomes one alert rule per discovered filesystem, disk or interface of this
// host, kept as the rule group `lld.<host>.<kind>`. An object that disappears drops its rule on
// the next pass. Placeholders `{{name}}`, `{{host}}` and every object label (`{{mountpoint}}`,
// `{{device}}`, `{{type}}`) are replaced; inside expr the values are escaped for a PromQL string.
type LLDConfig struct {
	APIURL     string         `json:"api_url"`
	Project    string         `json:"project"`
	APIKey     string         `json:"api_key"`  // a secret reference, needs alert-rule write
	Interval   string         `json:"interval"` // default 5m
	Host       string         `json:"host"`     // default: the OS host name
	Discovery  host.Discovery `json:"discovery"`
	Prototypes []Prototype    `json:"prototypes"`
}

// Prototype is a rule template for one object kind.
type Prototype struct {
	Kind        string            `json:"kind"` // filesystem, disk or nic
	Alert       string            `json:"alert"`
	Expr        string            `json:"expr"`
	For         string            `json:"for"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// LLDPrefix marks the groups the module owns.
const LLDPrefix = "lld."

var placeholder = regexp.MustCompile(`\{\{\s*([a-z_.]+)\s*\}\}`)

// fill replaces placeholders from vals; quote escapes values for a PromQL double-quoted string.
// An unknown placeholder is left as is so a typo stays visible in the rule.
func fill(s string, vals map[string]string, quote bool) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		v, ok := vals[placeholder.FindStringSubmatch(m)[1]]
		if !ok {
			return m
		}
		if quote {
			v = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
		}
		return v
	})
}

// LLDGroups instantiates the prototypes over objs: one group per kind, one rule per object,
// with the object's labels added to the rule labels. Kinds without objects yield no group.
func LLDGroups(hostName string, protos []Prototype, objs []host.Object) map[string]map[string]any {
	out := map[string]map[string]any{}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
	for _, p := range protos {
		for _, o := range objs {
			if o.Kind != p.Kind {
				continue
			}
			vals := map[string]string{"name": o.Name, "host": hostName}
			labels := map[string]string{"host_name": hostName, "lld_kind": o.Kind}
			for k, v := range o.Labels {
				vals[k], labels[k] = v, v
			}
			for k, v := range p.Labels {
				labels[k] = fill(v, vals, false)
			}
			ann := map[string]string{}
			for k, v := range p.Annotations {
				ann[k] = fill(v, vals, false)
			}
			rule := map[string]any{"alert": fill(p.Alert, vals, false), "expr": fill(p.Expr, vals, true),
				"labels": labels, "annotations": ann}
			if p.For != "" {
				rule["for"] = p.For
			}
			name := LLDPrefix + hostName + "." + o.Kind
			g, ok := out[name]
			if !ok {
				g = map[string]any{"name": name, "rules": []map[string]any{}}
				out[name] = g
			}
			g["rules"] = append(g["rules"].([]map[string]any), rule)
		}
	}
	return out
}

func (c LLDConfig) validate() error {
	if len(c.Prototypes) == 0 || len(c.Prototypes) > 50 {
		return errors.New("lld_rules: 1 to 50 prototypes")
	}
	for _, p := range c.Prototypes {
		switch p.Kind {
		case host.KindFilesystem, host.KindDisk, host.KindNIC:
		default:
			return fmt.Errorf("lld_rules: prototype kind %q: want filesystem, disk or nic", p.Kind)
		}
		if p.Alert == "" || p.Expr == "" {
			return errors.New("lld_rules: every prototype needs alert and expr")
		}
	}
	return c.Discovery.Validate()
}

// RunLLD syncs the instantiated groups until ctx ends.
func RunLLD(ctx context.Context, raw json.RawMessage) error {
	var c LLDConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("lld_rules: %w", err)
	}
	if err := c.validate(); err != nil {
		return err
	}
	every := 5 * time.Minute
	if c.Interval != "" {
		d, err := time.ParseDuration(c.Interval)
		if err != nil || d < 30*time.Second {
			return errors.New("lld_rules: interval must be a duration of at least 30s")
		}
		every = d
	}
	if c.Host == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("lld_rules: %w", err)
		}
		c.Host = h
	}
	if strings.ContainsAny(c.Host, "/ ") || len(LLDPrefix+c.Host+".filesystem") > 100 {
		return errors.New("lld_rules: host name too long or has / or a space for a rule group name")
	}
	api, err := ascode.New(c.APIURL, c.APIKey, c.Project, netguard.Guarded("agent", 30*time.Second))
	if err != nil {
		return fmt.Errorf("lld_rules: %w", err)
	}
	s := &syncer{
		want: func(context.Context) (map[string]map[string]any, error) {
			return LLDGroups(c.Host, c.Prototypes, host.Objects(c.Discovery)), nil
		},
		do: func(ctx context.Context, method, rel string, body any) error {
			return api.Do(ctx, method, rel, nil, body, nil)
		},
		synced: map[string][32]byte{},
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.once(ctx); err != nil {
			slog.Warn("lld_rules: sync failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
