package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/watchtowerobservability/watchtower-agent/agent/integrations"
)

// maxLogIntegrations bounds one agent's remote log integrations.
const maxLogIntegrations = 64

// Overlay lets remote config switch the logs module on and name integrations whose logs to tail
// (`{"enabled":true,"integrations":["nginx"]}`). The file globs are not remote input: they come
// from integrations.LogPaths, compiled into the agent, so a remote config still cannot make the
// agent read an arbitrary path.
func (m logsModule) Overlay(local, remote json.RawMessage) (json.RawMessage, error) {
	var r struct {
		Enabled      *bool    `json:"enabled"`
		Interval     string   `json:"interval"`
		Integrations []string `json:"integrations"`
	}
	dec := json.NewDecoder(bytes.NewReader(remote))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("remote config may only set enabled, interval and integrations: %w", err)
	}
	if len(r.Integrations) > maxLogIntegrations {
		return nil, errors.New("too many log integrations")
	}
	for _, n := range r.Integrations {
		if _, ok := integrations.LogPaths[n]; !ok {
			return nil, fmt.Errorf("integration %q has no log files", n)
		}
	}
	base, _ := json.Marshal(struct {
		Enabled  *bool  `json:"enabled,omitempty"`
		Interval string `json:"interval,omitempty"`
	}{r.Enabled, r.Interval})
	merged, err := m.toggle.Overlay(local, base)
	if err != nil || len(r.Integrations) == 0 {
		return merged, err
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(merged, &cfg); err != nil {
		return nil, err
	}
	cfg["integrations"], _ = json.Marshal(r.Integrations)
	return json.Marshal(cfg)
}

// Start adds the file tails of the enabled integrations (label agent.integration=<name>, which
// the server-side pipeline stages of that integration are guarded by) and runs the logs module.
func (m logsModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	cfg, err := expandLogIntegrations(cfg)
	if err != nil {
		return err
	}
	return logsRun(ctx, cfg, m.stateDir, out)
}

// expandLogIntegrations turns `integrations` into `files` entries, skipping a path the local file
// already tails.
func expandLogIntegrations(cfg json.RawMessage) (json.RawMessage, error) {
	var c map[string]json.RawMessage
	if len(cfg) == 0 || json.Unmarshal(cfg, &c) != nil || c["integrations"] == nil {
		return cfg, nil
	}
	var names []string
	if err := json.Unmarshal(c["integrations"], &names); err != nil {
		return nil, err
	}
	delete(c, "integrations")
	var files []json.RawMessage
	if c["files"] != nil {
		if err := json.Unmarshal(c["files"], &files); err != nil {
			return nil, err
		}
	}
	have := map[string]bool{}
	for _, f := range files {
		var s struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(f, &s)
		have[s.Path] = true
	}
	sort.Strings(names)
	for _, n := range names {
		for _, p := range integrations.LogPaths[n] {
			if have[p] {
				continue
			}
			have[p] = true
			f, _ := json.Marshal(map[string]any{"path": p, "labels": map[string]string{"agent.integration": n}})
			files = append(files, f)
		}
	}
	c["files"], _ = json.Marshal(files)
	return json.Marshal(c)
}
