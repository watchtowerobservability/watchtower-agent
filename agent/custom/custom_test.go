package custom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

type sample struct {
	kind  string
	name  string
	value float64
	attrs map[string]string
}

type rec struct {
	mu sync.Mutex
	s  []sample
}

func (r *rec) add(kind, name string, v float64, a map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.s = append(r.s, sample{kind, name, v, a})
}

func (r *rec) Gauge(name, _ string, v float64, a map[string]string, _ time.Time) {
	r.add("gauge", name, v, a)
}

func (r *rec) Sum(name, _ string, v float64, a map[string]string, _ time.Time) {
	r.add("sum", name, v, a)
}

func (r *rec) find(kind, name string, match map[string]string) (sample, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.s {
		if s.kind != kind || s.name != name {
			continue
		}
		ok := true
		for k, v := range match {
			ok = ok && s.attrs[k] == v
		}
		if ok {
			return s, true
		}
	}
	return sample{}, false
}

func TestNagiosPerfdataParse(t *testing.T) {
	got, err := ParsePerfdata(`time=0.123s;1;2;0;10 'free space'=512MB;100:200;50;0;1024 load=U cnt=7c broken`)
	if err == nil {
		t.Fatal("want an error for the unparseable items")
	}
	if len(got) != 3 {
		t.Fatalf("want 3 good items (U and 'broken' skipped), got %+v", got)
	}
	a := got[0]
	if a.Label != "time" || a.Value != 0.123 || a.UOM != "s" || *a.Warn != 1 || *a.Crit != 2 || *a.Min != 0 || *a.Max != 10 {
		t.Fatalf("time: %+v", a)
	}
	b := got[1]
	if b.Label != "free space" || b.Value != 512 || b.UOM != "MB" {
		t.Fatalf("quoted label: %+v", b)
	}
	if b.Warn != nil || *b.Crit != 50 || *b.Max != 1024 {
		t.Fatalf("a range threshold is dropped, the rest kept: %+v", b)
	}
	if got[2].UOM != "c" || got[2].Value != 7 {
		t.Fatalf("counter: %+v", got[2])
	}
}

func writePlugin(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestNagiosExitCodeMapping(t *testing.T) {
	for code, want := range map[int]Status{0: OK, 1: Warning, 2: Critical, 3: Unknown, 4: Unknown, 127: Unknown, -1: Unknown} {
		if got := Exit(code); got != want {
			t.Errorf("Exit(%d) = %v, want %v", code, got, want)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("shell plugins need a POSIX shell")
	}
	dir := t.TempDir()
	for code := range 4 {
		writePlugin(t, dir, fmt.Sprintf("check_%d", code), fmt.Sprintf("echo 'state %d | v=%d;5;9'\nexit %d\n", code, code, code))
	}
	writePlugin(t, dir, "check_env", "echo \"token=[$WT_AGENT_TOKEN]\"\nexit 0\n")
	n := Nagios{PluginDir: dir}
	t.Setenv("WT_AGENT_TOKEN", "wti_secret")
	for code := range 4 {
		r := n.RunCheck(context.Background(), CheckSpec{Plugin: fmt.Sprintf("check_%d", code)})
		if r.Status != Status(code) || len(r.Perf) != 1 || r.Perf[0].Value != float64(code) {
			t.Errorf("code %d: %+v", code, r)
		}
	}
	if r := n.RunCheck(context.Background(), CheckSpec{Plugin: "check_env"}); r.Text != "token=[]" {
		t.Errorf("plugin saw the agent environment: %q", r.Text)
	}
	for _, bad := range []string{"../etc/passwd", "/bin/sh", "a/b", "missing"} {
		if r := n.RunCheck(context.Background(), CheckSpec{Plugin: bad}); r.Status != Unknown {
			t.Errorf("%q must be UNKNOWN, got %v", bad, r.Status)
		}
	}
	rc := &rec{}
	Emit(rc, "disk", "check_1", map[string]string{"dc": "a"}, n.RunCheck(context.Background(), CheckSpec{Plugin: "check_1"}), time.Now())
	if s, ok := rc.find("gauge", "wt_check_status", map[string]string{"check": "disk", "status": "WARNING", "dc": "a"}); !ok || s.value != 1 {
		t.Errorf("wt_check_status missing: %+v", rc.s)
	}
	if s, ok := rc.find("gauge", "wt_check_perf_warn", map[string]string{"label": "v"}); !ok || s.value != 5 {
		t.Errorf("perf warn gauge missing: %+v", rc.s)
	}
}

func TestNagiosOverlayCannotNameProgramsOrArgs(t *testing.T) {
	n := Nagios{}
	local := json.RawMessage(`{"checks":[{"name":"disk","plugin":"check_disk","args":["-w","10%"],"interval":"60s"}]}`)
	for _, bad := range []string{
		`{"checks":[{"name":"disk","plugin":"negate"}]}`,
		`{"checks":[{"name":"disk","args":["x"]}]}`,
		`{"checks":[{"name":"disk","env":{"A":"b"}}]}`,
		`{"checks":[{"name":"new","enabled":true}]}`,
	} {
		if _, err := n.Overlay(local, json.RawMessage(bad)); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	out, err := n.Overlay(local, json.RawMessage(`{"checks":[{"name":"disk","enabled":false,"interval":"30s","labels":{"dc":"a"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var got NagiosConfig
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	c := got.Checks[0]
	if c.Plugin != "check_disk" || len(c.Args) != 2 || c.Interval != "30s" || c.Enabled == nil || *c.Enabled || c.Labels["dc"] != "a" {
		t.Fatalf("local program kept, remote toggles applied: %+v", c)
	}
}

func TestNagiosRefusesBatchFilesOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "check.bat"), []byte("@echo off\r\nexit 0\r\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := (Nagios{PluginDir: dir}).RunCheck(context.Background(), CheckSpec{Plugin: "check.bat"}); r.Status != Unknown {
		t.Fatalf("batch plugin ran: %+v", r)
	}
}

func TestNagiosTimeoutKillsChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell plugins need a POSIX shell")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "survived")
	writePlugin(t, dir, "check_hang", "(sleep 3; touch "+marker+") &\nsleep 30\n")
	r := (Nagios{PluginDir: dir}).RunCheck(context.Background(), CheckSpec{Plugin: "check_hang", Timeout: "1s"})
	if r.Status != Unknown {
		t.Fatalf("a timed-out plugin is UNKNOWN: %+v", r)
	}
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the plugin's child outlived the timeout")
	}
}

const exposition = `# TYPE http_requests_total counter
http_requests_total{code="200"} 1027 1700000000000
# TYPE temp gauge
temp 36.6
# TYPE lat histogram
lat_bucket{le="0.1"} 3
lat_bucket{le="+Inf"} 5
lat_sum 1.5
lat_count 5
`

func TestPrometheusScrapeToOTLP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, exposition)
	}))
	defer srv.Close()
	rc := &rec{}
	err := Prometheus{}.Scrape(context.Background(), TargetSpec{URL: srv.URL, Labels: map[string]string{"job": "x"}}, rc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := rc.find("sum", "http_requests_total", map[string]string{"code": "200", "job": "x"}); !ok || s.value != 1027 {
		t.Errorf("counter: %+v", rc.s)
	}
	if s, ok := rc.find("gauge", "temp", nil); !ok || s.value != 36.6 {
		t.Errorf("gauge: %+v", rc.s)
	}
	if s, ok := rc.find("sum", "lat_bucket", map[string]string{"le": "+Inf"}); !ok || s.value != 5 {
		t.Errorf("histogram bucket: %+v", rc.s)
	}
	if _, ok := rc.find("sum", "lat_count", nil); !ok {
		t.Errorf("histogram count: %+v", rc.s)
	}
}

func TestPrometheusOverlayAllowListAndKeepsLocal(t *testing.T) {
	p := Prometheus{Allow: []string{"localhost:9100"}}
	local := json.RawMessage(`{"targets":[{"url":"http://10.0.0.5:9999/metrics"}]}`)
	out, err := p.Overlay(local, json.RawMessage(`{"targets":[{"url":"http://localhost:9100/metrics"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var got PromConfig
	if err := json.Unmarshal(out, &got); err != nil || len(got.Targets) != 2 {
		t.Fatalf("local target kept and remote added: %v %+v", err, got)
	}
	for _, bad := range []string{"http://169.254.169.254/latest", "http://localhost:9101/", "file:///etc/passwd", "http://u:p@localhost:9100/"} {
		if _, err := p.Overlay(local, json.RawMessage(`{"targets":[{"url":"`+bad+`"}]}`)); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, err := (Prometheus{}).Overlay(local, json.RawMessage(`{"targets":[{"url":"http://localhost:9100/"}]}`)); err == nil {
		t.Error("an empty allow list lets remote config add no target")
	}
}
