// Package custom holds the customer-extensible check modules of wt-agent: Nagios-style plugins
// and Prometheus text-exposition scrapes.
package custom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Sink receives samples. The agent's OTLP exporter satisfies it.
type Sink interface {
	Gauge(name, unit string, value float64, attrs map[string]string, at time.Time)
	// Sum is a cumulative monotonic counter.
	Sum(name, unit string, value float64, attrs map[string]string, at time.Time)
}

const (
	defaultInterval = 60 * time.Second
	minInterval     = 5 * time.Second
	defaultTimeout  = 10 * time.Second
	maxTimeout      = 60 * time.Second
	maxOutput       = 64 << 10
	maxChecks       = 100
)

// Status is a Nagios plugin state.
type Status int

// The four Nagios states, equal to the plugin exit codes 0 to 3.
const (
	OK Status = iota
	Warning
	Critical
	Unknown
)

func (s Status) String() string {
	return [...]string{"OK", "WARNING", "CRITICAL", "UNKNOWN"}[s]
}

// CheckSpec is one plugin to run. Plugin and Args come only from the agent's own config file:
// Plugin is a bare file name inside plugin_dir and Args go to it as argv (no shell). Remote
// config can only set Enabled, Interval, Timeout and Labels of a check the file defines.
type CheckSpec struct {
	Name     string            `json:"name"`
	Plugin   string            `json:"plugin"`
	Args     []string          `json:"args"`
	Interval string            `json:"interval"`
	Timeout  string            `json:"timeout"`
	Enabled  *bool             `json:"enabled"`
	Labels   map[string]string `json:"labels"`
}

// RemoteCheck is all that remote config may say about a check.
type RemoteCheck struct {
	Name     string            `json:"name"`
	Enabled  *bool             `json:"enabled"`
	Interval string            `json:"interval"`
	Timeout  string            `json:"timeout"`
	Labels   map[string]string `json:"labels"`
}

// RemoteConfig is the nagios module config as the server may send it.
type RemoteConfig struct {
	Checks []RemoteCheck `json:"checks"`
}

// NagiosConfig is the module config.
type NagiosConfig struct {
	Checks []CheckSpec `json:"checks"`
}

// Nagios runs plugins from PluginDir.
type Nagios struct {
	PluginDir string
}

// PluginName reports whether p is a bare, plain file name.
func PluginName(p string) bool {
	if p == "" || len(p) > 100 || p == "." || p == ".." {
		return false
	}
	for _, c := range p {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// Overlay applies a remote-origin config to the local one. Remote entries must name a check the
// local file defines, may carry only name, enabled, interval, timeout and labels (unknown keys
// such as plugin, args or env fail the decode), and cannot add checks. Local checks the remote
// does not mention stay as they are.
func (n Nagios) Overlay(local, remote json.RawMessage) (json.RawMessage, error) {
	var lc NagiosConfig
	if len(local) > 0 {
		if err := json.Unmarshal(local, &lc); err != nil {
			return nil, err
		}
	}
	var rc RemoteConfig
	dec := json.NewDecoder(bytes.NewReader(remote))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("remote nagios config may only set name, enabled, interval, timeout and labels: %w", err)
	}
	if len(rc.Checks) > maxChecks {
		return nil, fmt.Errorf("at most %d nagios checks", maxChecks)
	}
	byName := map[string]int{}
	for i, c := range lc.Checks {
		byName[checkName(c)] = i
	}
	for _, r := range rc.Checks {
		i, ok := byName[r.Name]
		if !ok {
			return nil, fmt.Errorf("remote config names check %q, which the agent's own config does not define", r.Name)
		}
		c := &lc.Checks[i]
		if r.Enabled != nil {
			c.Enabled = r.Enabled
		}
		if r.Interval != "" {
			c.Interval = r.Interval
		}
		if r.Timeout != "" {
			c.Timeout = r.Timeout
		}
		if len(r.Labels) > 10 {
			return nil, errors.New("at most 10 labels per check")
		}
		if r.Labels != nil {
			c.Labels = r.Labels
		}
	}
	return json.Marshal(lc)
}

func checkName(c CheckSpec) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Plugin
}

// Result is one finished check.
type Result struct {
	Status Status
	Text   string
	Perf   []Perf
}

// Exit maps a plugin exit code to a status: 0 to 3 as is, anything else is UNKNOWN.
func Exit(code int) Status {
	if code >= 0 && code <= 3 {
		return Status(code)
	}
	return Unknown
}

// resolve finds the plugin inside dir. A symlink must stay inside dir after resolution.
func (n Nagios) resolve(plugin string) (string, error) {
	if n.PluginDir == "" {
		return "", errors.New("plugin_dir is not set in the agent config")
	}
	if !PluginName(plugin) {
		return "", fmt.Errorf("plugin %q is not a plain file name", plugin)
	}
	if ext := strings.ToLower(filepath.Ext(plugin)); runtime.GOOS == "windows" && (ext == ".bat" || ext == ".cmd") {
		return "", fmt.Errorf("plugin %q: batch files are refused on Windows (cmd.exe re-parses arguments)", plugin)
	}
	dir, err := filepath.EvalSymlinks(n.PluginDir)
	if err != nil {
		return "", err
	}
	p, err := filepath.EvalSymlinks(filepath.Join(dir, plugin))
	if err != nil {
		return "", err
	}
	if filepath.Dir(p) != dir {
		return "", fmt.Errorf("plugin %q resolves outside plugin_dir", plugin)
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("plugin %q is not a regular file", plugin)
	}
	return p, nil
}

type capWriter struct {
	buf bytes.Buffer
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := maxOutput - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// RunCheck runs one plugin. The plugin gets a minimal environment, never the agent's own (which
// holds the credential), and the output is capped.
func (n Nagios) RunCheck(ctx context.Context, spec CheckSpec) Result {
	path, err := n.resolve(spec.Plugin)
	if err != nil {
		return Result{Status: Unknown, Text: err.Error()}
	}
	timeout := parseDur(spec.Timeout, defaultTimeout, time.Second, maxTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, spec.Args...) // #nosec G204 -- path is resolved inside plugin_dir, no shell
	cmd.Env = minimalEnv()
	cmd.WaitDelay = time.Second
	killTreeOnCancel(cmd)
	out := &capWriter{}
	cmd.Stdout = out
	err = cmd.Run()
	text, perf := splitOutput(out.buf.String())
	switch {
	case ctx.Err() != nil:
		return Result{Status: Unknown, Text: "plugin timed out after " + timeout.String()}
	case err == nil:
		return Result{Status: OK, Text: text, Perf: perf}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Result{Status: Exit(ee.ExitCode()), Text: text, Perf: perf}
	}
	return Result{Status: Unknown, Text: err.Error()}
}

func minimalEnv() []string {
	if runtime.GOOS == "windows" {
		return []string{"SystemRoot=" + os.Getenv("SystemRoot")}
	}
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C"}
}

func parseDur(s string, def, lo, hi time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return min(max(d, lo), hi)
}

// splitOutput returns the text before the first '|' and the parsed performance data after it.
// Newlines in the perfdata part count as separators (long output may carry more of it).
func splitOutput(out string) (string, []Perf) {
	text, perf, found := strings.Cut(out, "|")
	text = strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	if !found {
		return text, nil
	}
	p, _ := ParsePerfdata(perf)
	return text, p
}

// Perf is one `label=value[UOM];warn;crit;min;max` datum. Thresholds that are not plain numbers
// (Nagios ranges such as `10:20`) are left nil.
type Perf struct {
	Label                string
	Value                float64
	UOM                  string
	Warn, Crit, Min, Max *float64
}

// ParsePerfdata parses the Nagios performance data format. Unparseable items are skipped and
// reported in the error; the good ones are still returned.
func ParsePerfdata(s string) ([]Perf, error) {
	var out []Perf
	var bad []string
	for _, tok := range splitPerf(s) {
		p, err := parsePerf(tok)
		if err != nil {
			bad = append(bad, tok)
			continue
		}
		out = append(out, p)
	}
	if len(bad) > 0 {
		return out, fmt.Errorf("unparseable perfdata: %s", strings.Join(bad, " "))
	}
	return out, nil
}

// splitPerf splits on whitespace outside single quotes.
func splitPerf(s string) []string {
	var toks []string
	var cur strings.Builder
	quoted := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '\'':
			quoted = !quoted
			cur.WriteRune(r)
		case !quoted && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

func parsePerf(tok string) (Perf, error) {
	label, rest, ok := strings.Cut(tok, "=")
	if !ok {
		return Perf{}, errors.New("no '='")
	}
	label = strings.Trim(label, "'")
	if label == "" {
		return Perf{}, errors.New("empty label")
	}
	parts := strings.Split(rest, ";")
	num, uom := splitUOM(parts[0])
	v, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return Perf{}, err
	}
	p := Perf{Label: label, Value: v, UOM: uom}
	for i, dst := range []**float64{&p.Warn, &p.Crit, &p.Min, &p.Max} {
		if i+1 < len(parts) {
			if f, err := strconv.ParseFloat(parts[i+1], 64); err == nil {
				*dst = &f
			}
		}
	}
	return p, nil
}

func splitUOM(s string) (num, uom string) {
	i := strings.IndexFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+' || r == 'e' || r == 'E')
	})
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

// Emit turns a result into samples: `wt_check_status` (0 to 3) and one gauge per perfdata item.
func Emit(out Sink, check, plugin string, labels map[string]string, r Result, at time.Time) {
	addLabels := func(m map[string]string) map[string]string {
		for k, v := range labels {
			if _, taken := m[k]; !taken {
				m[k] = v
			}
		}
		return m
	}
	st := map[string]string{"check": check, "plugin": plugin, "status": r.Status.String()}
	out.Gauge("wt_check_status", "", float64(r.Status), addLabels(st), at)
	for _, p := range r.Perf {
		a := map[string]string{"check": check, "plugin": plugin, "label": p.Label}
		if p.UOM != "" {
			a["uom"] = p.UOM
		}
		a = addLabels(a)
		out.Gauge("wt_check_perf_value", p.UOM, p.Value, a, at)
		for name, v := range map[string]*float64{
			"wt_check_perf_warn": p.Warn, "wt_check_perf_crit": p.Crit,
			"wt_check_perf_min": p.Min, "wt_check_perf_max": p.Max,
		} {
			if v != nil {
				out.Gauge(name, p.UOM, *v, a, at)
			}
		}
	}
}

// Run schedules every check until ctx ends.
func (n Nagios) Run(ctx context.Context, raw json.RawMessage, out Sink) error {
	var c NagiosConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if len(c.Checks) > maxChecks {
		return fmt.Errorf("at most %d nagios checks", maxChecks)
	}
	done := make(chan struct{}, len(c.Checks))
	for _, spec := range c.Checks {
		if spec.Enabled != nil && !*spec.Enabled {
			done <- struct{}{}
			continue
		}
		go func() {
			defer func() { done <- struct{}{} }()
			n.loop(ctx, spec, out)
		}()
	}
	for range c.Checks {
		<-done
	}
	<-ctx.Done()
	return nil
}

func (n Nagios) loop(ctx context.Context, spec CheckSpec, out Sink) {
	name := checkName(spec)
	t := time.NewTicker(parseDur(spec.Interval, defaultInterval, minInterval, 24*time.Hour))
	defer t.Stop()
	for {
		Emit(out, name, spec.Plugin, spec.Labels, n.RunCheck(ctx, spec), time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
