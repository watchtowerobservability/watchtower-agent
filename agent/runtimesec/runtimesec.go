// Package runtimesec is the agent's Workload Protection module (Datadog-parity D1): eBPF
// exec/file/network hooks that match a default policy and emit security signals to the same store
// the Cloud SIEM detection engine fills (ClickHouse security_signals_v1, via the hosted
// /v1/security intake). The signals carry the same shape the engine's drafts do.
//
// The probes live in bpf/runtimesec.bpf.c (exec/file/network), compiled to objects/runtimesec_bpfel.o
// by `make ebpf-gen` and embedded (loader_linux.go). The loader attaches them, reads the ring buffer,
// decodes each event (event.go), matches it against the policy, resolves the pid's container service
// name, and calls Emitter.Signal. On non-Linux the module is a no-op (loader_other.go).
//
// shortcut: the committed objects/ holds only a placeholder; a build that skipped `make ebpf-gen`
// embeds no object and the loader fails preflight with a message saying to run it. Upgrade by
// running ebpf-gen in the release image (item #5, cross-repo).
package runtimesec

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Sink is the subset of the agent exporter this module needs (satisfied structurally by the
// agent's Exporter).
type Sink interface {
	Log(severity, body string, attrs map[string]string, at time.Time)
}

// Rule is one runtime policy rule. A hit on an enabled rule emits a signal.
type Rule struct {
	// ID is the stable rule id carried on the signal.
	ID string `json:"id"`
	// Kind is exec | file | network.
	Kind string `json:"kind"`
	// Severity of the emitted signal: info|low|medium|high|critical.
	Severity string `json:"severity"`
	// Match is the kind-specific matcher (comms, paths, ports); opaque to Go, read by the probe.
	Match map[string]any `json:"match"`
	// Action is alert | block. block requires an LSM/enforcing probe (follow-up).
	Action string `json:"action"`
}

// Policy is the runtime-security ruleset.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Config is the module's own config (local file; remote may only toggle enabled).
type Config struct {
	Enabled bool    `json:"enabled"`
	Policy  *Policy `json:"policy,omitempty"`
	// ObjectDir holds runtimesec_bpfel.o when the agent was built without embedded objects.
	ObjectDir string `json:"object_dir,omitempty"`
	// RingBufferKB sizes the events ring buffer (power of two >= 64, default 256).
	RingBufferKB int `json:"ring_buffer_kb,omitempty"`
	// MaxEventsPerSec caps emitted signals so a noisy host cannot flood the pipeline (default 500).
	MaxEventsPerSec int `json:"max_events_per_sec,omitempty"`
}

func (c *Config) defaults() error {
	if c.ObjectDir == "" {
		c.ObjectDir = "/usr/lib/wt-agent/ebpf"
	}
	if c.RingBufferKB <= 0 {
		c.RingBufferKB = 256
	}
	if c.RingBufferKB&(c.RingBufferKB-1) != 0 || c.RingBufferKB < 64 {
		return fmt.Errorf("ring_buffer_kb %d must be a power of two >= 64", c.RingBufferKB)
	}
	if c.MaxEventsPerSec <= 0 {
		c.MaxEventsPerSec = 500
	}
	return nil
}

var (
	validKinds   = map[string]bool{"exec": true, "file": true, "network": true}
	validSev     = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	validActions = map[string]bool{"alert": true, "block": true}
)

// DefaultPolicy is the baseline ruleset applied when the config names none: the same ground Falco's
// default rules cover (a shell in a container, writes under system binaries, outbound to a
// non-standard port).
func DefaultPolicy() Policy {
	return Policy{Rules: []Rule{
		{ID: "shell_in_container", Kind: "exec", Severity: "high", Action: "alert",
			Match: map[string]any{"comm": []string{"sh", "bash", "zsh", "ash"}, "in_container": true}},
		{ID: "write_below_system_bin", Kind: "file", Severity: "high", Action: "alert",
			Match: map[string]any{"op": "write", "paths": []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"}}},
		{ID: "sensitive_file_read", Kind: "file", Severity: "medium", Action: "alert",
			Match: map[string]any{"op": "read", "paths": []string{"/etc/shadow", "/root/.ssh"}}},
		{ID: "write_sensitive_file", Kind: "file", Severity: "high", Action: "alert",
			Match: map[string]any{"op": "write", "paths": []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d"}}},
		{ID: "unexpected_outbound", Kind: "network", Severity: "medium", Action: "alert",
			Match: map[string]any{"direction": "egress", "deny_ports": []int{0}}},
	}}
}

// Validate rejects a malformed policy (every rule needs a known kind, severity and action).
func (p Policy) Validate() error {
	for i, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule %d: id required", i)
		}
		if !validKinds[r.Kind] {
			return fmt.Errorf("rule %s: kind must be exec|file|network", r.ID)
		}
		if !validSev[r.Severity] {
			return fmt.Errorf("rule %s: bad severity %q", r.ID, r.Severity)
		}
		if !validActions[r.Action] {
			return fmt.Errorf("rule %s: action must be alert|block", r.ID)
		}
	}
	return nil
}

// Emitter shapes a policy hit into a security signal and ships it through the sink. It is what the
// (follow-up) eBPF ring-buffer reader calls on each match.
type Emitter struct {
	out  Sink
	host string
}

// NewEmitter builds an emitter bound to a sink and host identity.
func NewEmitter(out Sink, host string) *Emitter { return &Emitter{out: out, host: host} }

// Signal emits one runtime-security signal: the entity is the process/container, the body names
// the rule. These land as logs with wt.security.* attributes; the hosted pipeline turns them into
// security_signals_v1 rows (same path as the SIEM engine).
func (e *Emitter) Signal(rule Rule, entity string, detail map[string]string) {
	attrs := map[string]string{
		"wt.security.source":   "runtime_security",
		"wt.security.rule_id":  rule.ID,
		"wt.security.severity": rule.Severity,
		"wt.security.kind":     rule.Kind,
		"wt.security.entity":   entity,
		"host.name":            e.host,
	}
	for k, v := range detail {
		attrs["wt.security.detail."+k] = v
	}
	e.out.Log(rule.Severity, "runtime_security: "+rule.ID+" on "+entity, attrs, time.Now())
}

// Run parses the config, builds the policy and (when enabled) loads the eBPF probes that feed
// Emitter.Signal. The probe loading is platform-specific: loadAndRun lives in loader_linux.go
// (real probes) and loader_other.go (no-op that logs and waits).
func Run(ctx context.Context, raw json.RawMessage, out Sink, host string) error {
	cfg := Config{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("runtime_security config: %w", err)
		}
	}
	if !cfg.Enabled {
		return nil
	}
	if err := cfg.defaults(); err != nil {
		return err
	}
	pol := DefaultPolicy()
	if cfg.Policy != nil {
		pol = *cfg.Policy
	}
	if err := pol.Validate(); err != nil {
		return err
	}
	return loadAndRun(ctx, cfg, pol, NewEmitter(out, host), out, host)
}
