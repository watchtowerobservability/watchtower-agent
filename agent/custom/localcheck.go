package custom

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// LocalChecks runs Checkmk-style local checks: every executable in Dir prints lines of
//
//	<status> <service> <perfdata> <text>
//
// where status is 0-3 or P (computed from the perfdata thresholds), service may be "quoted",
// perfdata is `-` or `name=value;warn;crit;min;max|...`. Lines between `<<<<host>>>>` and
// `<<<<>>>>` are piggyback data: they are reported with that host.name instead of the agent's.
// Dir comes only from the agent's own config file; remote config can only toggle the module.
type LocalChecks struct{}

// LocalConfig is the local_checks module config.
type LocalConfig struct {
	Dir      string            `json:"dir"`
	Interval string            `json:"interval"` // default 60s
	Timeout  string            `json:"timeout"`  // per script, default 10s
	Labels   map[string]string `json:"labels"`
}

// LocalResult is one parsed local-check line.
type LocalResult struct {
	Host    string // piggyback host, "" for the agent's own host
	Service string
	Result
}

// Run executes the scripts on the interval until ctx ends.
func (LocalChecks) Run(ctx context.Context, raw json.RawMessage, out Sink) error {
	var c LocalConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if c.Dir == "" {
		return errors.New("local_checks: dir is not set")
	}
	t := time.NewTicker(parseDur(c.Interval, defaultInterval, minInterval, 24*time.Hour))
	defer t.Stop()
	for {
		now := time.Now()
		for _, script := range localScripts(c.Dir) {
			for _, r := range ParseLocal(runLocal(ctx, script, parseDur(c.Timeout, defaultTimeout, time.Second, maxTimeout))) {
				EmitLocal(out, filepath.Base(script), c.Labels, r, now)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// localScripts lists the regular executable files directly in dir (symlinks must stay inside).
func localScripts(dir string) []string {
	d, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil
	}
	ents, err := os.ReadDir(d)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		p, err := filepath.EvalSymlinks(filepath.Join(d, e.Name()))
		if err != nil || filepath.Dir(p) != d || !PluginName(e.Name()) {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && (st.Mode()&0o111 != 0 || isWindowsExe(p)) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func isWindowsExe(p string) bool {
	return strings.EqualFold(filepath.Ext(p), ".exe")
}

func runLocal(ctx context.Context, path string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path) // #nosec G204 -- a file inside the operator's local-check dir, no shell
	cmd.Env = minimalEnv()
	cmd.WaitDelay = time.Second
	killTreeOnCancel(cmd)
	w := &capWriter{}
	cmd.Stdout = w
	_ = cmd.Run() // a failing script still reports the lines it printed
	return w.buf.String()
}

// ParseLocal parses local-check output, including piggyback blocks. Bad lines are skipped.
func ParseLocal(out string) []LocalResult {
	var res []LocalResult
	host := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if h, ok := strings.CutPrefix(line, "<<<<"); ok && strings.HasSuffix(h, ">>>>") {
			host = strings.TrimSuffix(h, ">>>>")
			if len(host) > 253 || strings.ContainsAny(host, " \t/") {
				host = "" // not a host name: keep reporting as ourselves
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "<<<") {
			continue // section headers such as <<<local:sep(0)>>>
		}
		if r, ok := parseLocalLine(line); ok {
			r.Host = host
			res = append(res, r)
		}
	}
	return res
}

func parseLocalLine(line string) (LocalResult, bool) {
	st, rest, ok := strings.Cut(line, " ")
	if !ok {
		return LocalResult{}, false
	}
	rest = strings.TrimLeft(rest, " ")
	var svc string
	if q, ok := strings.CutPrefix(rest, `"`); ok {
		svc, rest, ok = strings.Cut(q, `"`)
		if !ok {
			return LocalResult{}, false
		}
	} else {
		svc, rest, _ = strings.Cut(rest, " ")
	}
	rest = strings.TrimLeft(rest, " ")
	perfTok, text, _ := strings.Cut(rest, " ")
	if svc == "" || len(svc) > 200 {
		return LocalResult{}, false
	}
	var perf []Perf
	if perfTok != "-" && perfTok != "" {
		perf, _ = ParsePerfdata(strings.ReplaceAll(perfTok, "|", " "))
	}
	r := LocalResult{Service: svc, Result: Result{Text: strings.TrimSpace(text), Perf: perf}}
	switch st {
	case "0", "1", "2", "3":
		r.Status = Status(st[0] - '0')
	case "P":
		r.Status = computedStatus(perfTok)
	default:
		return LocalResult{}, false
	}
	return r, true
}

// computedStatus is the worst state over the perfdata thresholds: `warn;crit` are upper limits,
// `lo:hi` ranges are bounds on both sides (Checkmk's P status).
func computedStatus(perfTok string) Status {
	worst := OK
	for _, tok := range strings.Split(perfTok, "|") {
		_, rest, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		parts := strings.Split(rest, ";")
		num, _ := splitUOM(parts[0])
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return Unknown
		}
		for i, s := range []Status{Warning, Critical} {
			if i+1 < len(parts) && outside(v, parts[i+1]) && s > worst {
				worst = s
			}
		}
	}
	return worst
}

// outside reports whether v breaches threshold t: a plain number is an upper limit, `lo:hi` a range.
func outside(v float64, t string) bool {
	if t == "" {
		return false
	}
	if lo, hi, ok := strings.Cut(t, ":"); ok {
		l, e1 := strconv.ParseFloat(lo, 64)
		h, e2 := strconv.ParseFloat(hi, 64)
		return (e1 == nil && v < l) || (e2 == nil && v > h)
	}
	f, err := strconv.ParseFloat(t, 64)
	return err == nil && v >= f
}

// resSink is implemented by the agent exporter: it accepts resource attributes per sample.
type resSink interface {
	GaugeRes(name, unit string, value float64, res, attrs map[string]string, at time.Time)
	SumRes(name, unit string, value float64, res, attrs map[string]string, at time.Time)
}

// piggySink reports samples as another host (resource host.name), for piggyback blocks.
type piggySink struct {
	rs  resSink
	res map[string]string
}

func (p piggySink) Gauge(n, u string, v float64, a map[string]string, at time.Time) {
	p.rs.GaugeRes(n, u, v, p.res, a, at)
}

func (p piggySink) Sum(n, u string, v float64, a map[string]string, at time.Time) {
	p.rs.SumRes(n, u, v, p.res, a, at)
}

// EmitLocal writes one local-check result as wt_check_status and wt_check_perf_* (the nagios
// series, plugin = script), on the piggyback host when the line came from such a block.
func EmitLocal(out Sink, script string, labels map[string]string, r LocalResult, at time.Time) {
	if r.Host != "" {
		rs, ok := out.(resSink)
		if !ok {
			return // an exporter without resource support cannot tell the hosts apart: drop, never misattribute
		}
		out = piggySink{rs: rs, res: map[string]string{"host.name": r.Host}}
		labels = sink.With(labels, "wt_piggyback_source", "local_checks")
	}
	Emit(out, r.Service, script, labels, r.Result, at)
}
