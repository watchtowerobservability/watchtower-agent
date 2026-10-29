// Package integrations holds the integration manifests (what a product looks like, what to
// alert on) and the database, queue and service collectors that feed them. Credentials and
// addresses come only from the agent's own config file; remote config may switch a module on or
// off and change its interval (see modules_infra.go).
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Manifest is one integrations/<name>/manifest.yaml (shape: integrations/schema.json).
type Manifest struct {
	Name       string       `yaml:"name" json:"name"`
	Version    string       `yaml:"version" json:"version"`
	Discovery  Discovery    `yaml:"discovery" json:"discovery"`
	Module     ModuleRef    `yaml:"module" json:"module"`
	Metrics    []MetricDoc  `yaml:"metrics" json:"metrics"`
	Dashboards []any        `yaml:"dashboards" json:"dashboards"`
	Alerts     []AlertDoc   `yaml:"alerts" json:"alerts"`
	DependsOn  []Dependency `yaml:"depends_on" json:"depends_on"`
}

// Discovery says how a running product is recognized.
type Discovery struct {
	ProcessNames []string          `yaml:"process_names" json:"process_names"`
	Ports        []int             `yaml:"ports" json:"ports"`
	K8sLabels    map[string]string `yaml:"k8s_labels" json:"k8s_labels"`
}

// ModuleRef names the agent module that collects the product and its local config defaults.
type ModuleRef struct {
	Kind           string         `yaml:"kind" json:"kind"`
	ConfigDefaults map[string]any `yaml:"config_defaults" json:"config_defaults"`
}

// MetricDoc documents one emitted metric.
type MetricDoc struct {
	Name        string `yaml:"name" json:"name"`
	Unit        string `yaml:"unit" json:"unit"`
	Description string `yaml:"description" json:"description"`
}

// AlertDoc is one stock alert: a rule document (the API validates it as a RuleSpec).
type AlertDoc struct {
	Name               string         `yaml:"name" json:"name"`
	Rule               map[string]any `yaml:"rule" json:"rule"`
	ThresholdRationale string         `yaml:"threshold_rationale" json:"threshold_rationale"`
	RunbookURL         string         `yaml:"runbook_url" json:"runbook_url"`
	DefaultEnabled     bool           `yaml:"default_enabled" json:"default_enabled"`
}

// Dependency makes this product's alerts depend on another kind's "down" alert: while the
// parent is firing for the same values of EqualLabels, the children are inhibited.
type Dependency struct {
	ParentKind  string   `yaml:"parent_kind" json:"parent_kind"`
	EqualLabels []string `yaml:"equal_labels" json:"equal_labels"`
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

// Parse decodes one manifest strictly (unknown fields are an error) and validates it.
func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, m.Validate()
}

// Validate checks what integrations/schema.json states.
func (m *Manifest) Validate() error {
	if !nameRE.MatchString(m.Name) {
		return fmt.Errorf("name %q must match %s", m.Name, nameRE)
	}
	if m.Version == "" || m.Module.Kind == "" {
		return errors.New("version and module.kind are required")
	}
	for _, p := range m.Discovery.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	seen := map[string]bool{}
	for _, mt := range m.Metrics {
		if mt.Name == "" || mt.Description == "" || seen[mt.Name] {
			return fmt.Errorf("metric %q: name and description required, names unique", mt.Name)
		}
		seen[mt.Name] = true
	}
	alerts := map[string]bool{}
	for _, a := range m.Alerts {
		if a.Name == "" || alerts[a.Name] || a.ThresholdRationale == "" || a.Rule == nil {
			return fmt.Errorf("alert %q: name (unique), rule and threshold_rationale required", a.Name)
		}
		alerts[a.Name] = true
		if _, ok := a.Rule["query"]; !ok {
			return fmt.Errorf("alert %q: rule has no query", a.Name)
		}
	}
	for _, d := range m.DependsOn {
		if !nameRE.MatchString(d.ParentKind) || d.ParentKind == m.Name || len(d.EqualLabels) == 0 {
			return fmt.Errorf("depends_on %q: a different parent kind and equal_labels are required", d.ParentKind)
		}
	}
	return nil
}

// LoadFS reads <dir>/manifest.yaml for every directory of fsys, sorted by name.
func LoadFS(fsys fs.FS) ([]*Manifest, error) {
	ents, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name()+"/manifest.yaml")
		if err != nil {
			continue // a directory without a manifest (snmp's MIB files) is not an integration
		}
		m, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if m.Name != e.Name() {
			return nil, fmt.Errorf("%s: name %q differs from the directory", e.Name(), m.Name)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// checker is a module config that can say whether it is usable.
type checker interface{ check() error }

// load decodes raw strictly (a misspelt key is an error, not a silently ignored setting) and
// checks the required fields.
func load(raw json.RawMessage, c checker) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return err
	}
	return c.check()
}

// ValidateConfig checks a module config of kind (a manifest's module.kind) the way the module
// does when it starts. Kinds that are not one of this package's modules (host, prometheus) are
// validated by their own packages.
func ValidateConfig(kind string, raw json.RawMessage) error {
	mk := map[string]func() checker{
		"postgres":    func() checker { return &PostgresConfig{} },
		"mysql":       func() checker { return &MySQLConfig{} },
		"redis":       func() checker { return &RedisConfig{} },
		"memcached":   func() checker { return &MemcachedConfig{} },
		"mongodb":     func() checker { return &MongoConfig{} },
		"kafka":       func() checker { return &KafkaConfig{} },
		"rabbitmq":    func() checker { return &HTTPConfig{} },
		"nats":        func() checker { return &HTTPConfig{} },
		"http_status": func() checker { return &HTTPStatusConfig{} },
		"listen":      func() checker { return &ListenConfig{} },
		"docker":      func() checker { return &DockerConfig{} },
		"jmx":         func() checker { return &JolokiaConfig{} },
		"activemq":    func() checker { return &JolokiaConfig{} },
		"mssql":       func() checker { return &ExporterConfig{} },
		"oracle":      func() checker { return &ExporterConfig{} },
		"cassandra":   func() checker { return &ExporterConfig{} },
		"consul":      func() checker { return &ExporterConfig{} },
		"vault":       func() checker { return &ExporterConfig{} },
		"windows":     func() checker { return &ExporterConfig{} },
		"hyperv":      func() checker { return &ExporterConfig{} },
		"ceph":        func() checker { return &ExporterConfig{} },
		"kinesis":     func() checker { return &ExporterConfig{} },
		"pulsar":      func() checker { return &ExporterConfig{} },
	}[kind]
	if mk == nil {
		return fmt.Errorf("module %q is not validated here", kind)
	}
	return load(raw, mk())
}

// Base is the part of every module config that remote config may change.
type Base struct {
	Enabled  *bool  `json:"enabled"`
	Interval string `json:"interval"`
}

// Loop runs collect every interval (default def, at least 5 s) until ctx ends and reports
// `wt.integration.up` (1 or 0) per round, so an unreachable product is an alertable series. A
// disabled module just waits.
func Loop(ctx context.Context, name string, b Base, def time.Duration, out sink.Sink,
	collect func(ctx context.Context, now time.Time) error,
) error {
	if b.Enabled != nil && !*b.Enabled {
		<-ctx.Done()
		return nil
	}
	every := def
	if d, err := time.ParseDuration(b.Interval); err == nil && d > 0 {
		every = max(d, 5*time.Second)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, min(every, 30*time.Second))
		now := time.Now()
		err := collect(rctx, now)
		cancel()
		up := 1.0
		if err != nil {
			up = 0
			slog.Warn("integration collect failed", "integration", name, "error", sink.Truncate(err.Error(), 300))
		}
		out.Gauge("wt.integration.up", "1", up, map[string]string{"integration": name}, now)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
