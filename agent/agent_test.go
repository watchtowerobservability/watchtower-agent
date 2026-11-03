package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"
)

func TestRemoteConfigSelectorSpecificity(t *testing.T) {
	labels := map[string]string{"role": "db", "env": "prod"}
	all := []Candidate{
		{Name: "all", Selector: map[string]string{}, CreatedAt: 30, Version: 3},
		{Name: "role", Selector: map[string]string{"role": "db"}, CreatedAt: 10, Version: 1},
		{Name: "both-old", Selector: map[string]string{"role": "db", "env": "prod"}, CreatedAt: 10, Version: 2},
		{Name: "both-new", Selector: map[string]string{"role": "db", "env": "prod"}, CreatedAt: 20, Version: 4},
		{Name: "other", Selector: map[string]string{"role": "web", "x": "y"}, CreatedAt: 40, Version: 5},
	}
	if got, ok := Select(labels, all); !ok || got.Name != "both-new" {
		t.Fatalf("most matchers then newest: got %+v", got)
	}
	if got, _ := Select(map[string]string{}, all); got.Name != "all" {
		t.Fatalf("an unlabelled agent gets the empty selector: got %+v", got)
	}
	if _, ok := Select(labels, all[4:]); ok {
		t.Fatal("a selector that does not match must not be served")
	}
}

func served(token, agent, configID string, version int, gen int64, sel, body string) *Served {
	sum := sha256.Sum256([]byte(body))
	sv := &Served{Version: version, Gen: gen, ConfigID: configID, Selector: sel, SHA256: hex.EncodeToString(sum[:]), Body: body}
	sv.MAC = macOf(token, agent, sv)
	return sv
}

func TestServedConfigIsVerified(t *testing.T) {
	const tok, agent = "wti_abcdefgh_secret", "agt_1"
	labels := map[string]string{"role": "db"}
	body := `{"modules":{"nagios":{"checks":[]}}}`
	good := served(tok, agent, "acf_1", 3, 7, `{"role":"db"}`, body)
	rc, err := good.Verify(tok, agent, labels)
	if err != nil || len(rc.Modules) != 1 {
		t.Fatalf("good config: %v %+v", err, rc)
	}
	tampered := *good
	tampered.Body = `{"modules":{"nagios":{"checks":[{"name":"x"}]}}}`
	if _, err := tampered.Verify(tok, agent, labels); err == nil {
		t.Error("a changed body must fail the hash")
	}
	sum := sha256.Sum256([]byte(tampered.Body))
	tampered.SHA256 = hex.EncodeToString(sum[:])
	if _, err := tampered.Verify(tok, agent, labels); err == nil {
		t.Error("a body with a fixed-up hash but no valid signature must fail")
	}
	wide := *good
	wide.Selector = `{}`
	if _, err := wide.Verify(tok, agent, labels); err == nil {
		t.Error("the selector is signed: widening it must fail")
	}
	for name, mutate := range map[string]func(*Served){
		"version":   func(s *Served) { s.Version = 9 },
		"config id": func(s *Served) { s.ConfigID = "acf_2" },
		"gen":       func(s *Served) { s.Gen = 1 },
	} {
		c := *good
		mutate(&c)
		if _, err := c.Verify(tok, agent, labels); err == nil {
			t.Errorf("a changed %s must fail the signature", name)
		}
	}
	if _, err := good.Verify("wti_other_token", agent, labels); err == nil {
		t.Error("another token's signature must fail")
	}
	if _, err := good.Verify(tok, "agt_2", labels); err == nil {
		t.Error("a config signed for another agent must fail")
	}
	if _, err := good.Verify(tok, agent, map[string]string{"role": "web"}); err == nil {
		t.Error("a selector that does not match this agent must fail")
	}
	extra := served(tok, agent, "acf_1", 4, 8, `{}`, `{"modules":{},"exec":"rm -rf /"}`)
	if _, err := extra.Verify(tok, agent, labels); err == nil {
		t.Error("unknown keys must be refused")
	}
}

func TestSelectorOnAgentIDMatchesTheAgentsOwnID(t *testing.T) {
	const tok, agent = "wti_abcdefgh_secret", "agt_1"
	body := `{"modules":{}}`
	mine := served(tok, agent, "acf_1", 3, 7, `{"wt.agent.id":"agt_1"}`, body)
	if _, err := mine.Verify(tok, agent, map[string]string{}); err != nil {
		t.Fatalf("a selector naming this agent's id must match: %v", err)
	}
	// a label with that key in the agent's own file cannot stand in for the id
	spoof := served(tok, agent, "acf_1", 3, 7, `{"wt.agent.id":"agt_2"}`, body)
	if _, err := spoof.Verify(tok, agent, map[string]string{"wt.agent.id": "agt_2"}); err == nil {
		t.Error("a local label must not override the agent id")
	}
	other := served(tok, agent, "acf_1", 3, 7, `{"wt.agent.id":"agt_2"}`, body)
	if _, err := other.Verify(tok, agent, nil); err == nil {
		t.Error("a selector naming another agent must not match")
	}
}

func TestOlderConfigVersionIsRefusedAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	ap := LoadApplied(dir)
	ap.Record(&Served{ConfigID: "acf_1", Version: 5, Gen: 10})
	if err := ap.Check(&Served{ConfigID: "acf_1", Version: 4, Gen: 10}); err == nil {
		t.Error("a replayed older version must be refused")
	}
	if err := LoadApplied(dir).Check(&Served{ConfigID: "acf_1", Version: 4, Gen: 10}); err == nil {
		t.Error("the refusal must survive a restart")
	}
	if err := ap.Check(&Served{ConfigID: "acf_1", Version: 6, Gen: 11}); err != nil {
		t.Error(err)
	}
	if err := ap.Check(&Served{ConfigID: "", Version: 0, Gen: 11}); err != nil {
		t.Error("a current empty config (version 0) must be accepted:", err)
	}
	// replays that a per-config version check alone would let through
	if err := ap.Check(&Served{ConfigID: "", Version: 0, Gen: 3}); err == nil {
		t.Error("an old empty config must be refused by generation")
	}
	if err := ap.Check(&Served{ConfigID: "acf_other", Version: 1, Gen: 4}); err == nil {
		t.Error("an old config of another id must be refused by generation")
	}
}

func TestAppliedFileWrittenAtomicallyAndTornFileIsSurvivable(t *testing.T) {
	dir := t.TempDir()
	ap := LoadApplied(dir)
	ap.Record(&Served{ConfigID: "acf_1", Version: 2, Gen: 5})
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Fatalf("temp files left behind: %v", m)
	}
	if err := os.WriteFile(filepath.Join(dir, "applied.json"), []byte(`{"gen": 5, "v": {`), 0o600); err != nil {
		t.Fatal(err)
	}
	torn := LoadApplied(dir)
	if torn.V == nil {
		t.Fatal("a torn file must still give a usable map")
	}
	torn.Record(&Served{ConfigID: "acf_1", Version: 3, Gen: 6})
	if got := LoadApplied(dir); got.Gen != 6 || got.V["acf_1"] != 3 {
		t.Fatalf("the next write must replace the torn file: %+v", got)
	}
}

func TestMergeKeepsLocalPolicyAndRefusesRemoteTricks(t *testing.T) {
	local := &LocalConfig{PluginDir: t.TempDir(), ScrapeAllow: []string{"localhost:9100"}}
	reg := NewRegistry(local)
	localMods := map[string]json.RawMessage{
		"nagios": json.RawMessage(`{"checks":[{"name":"disk","plugin":"check_disk","args":["-w","10%"]}]}`),
	}
	remote := &RemoteConfig{Modules: map[string]json.RawMessage{
		"prometheus": json.RawMessage(`{"targets":[{"url":"http://169.254.169.254/"}]}`),
		"agent":      json.RawMessage(`{"anything":true}`),
		"nosuch":     json.RawMessage(`{}`),
	}}
	var warns []string
	p := Merge(reg, localMods, remote, func(m string) { warns = append(warns, m) })
	if p["prometheus"] != nil || p["nosuch"] != nil || string(p["agent"]) != `{}` {
		t.Fatalf("plan: %v", p)
	}
	if len(warns) != 3 {
		t.Fatalf("each refusal must be reported: %v", warns)
	}
	ok := &RemoteConfig{Modules: map[string]json.RawMessage{"nagios": json.RawMessage(`{"checks":[{"name":"disk","enabled":false}]}`)}}
	p = Merge(reg, localMods, ok, func(m string) { t.Fatal(m) })
	if !strings.Contains(string(p["nagios"]), `"plugin":"check_disk"`) || !strings.Contains(string(p["nagios"]), `"enabled":false`) {
		t.Fatalf("toggle applied on top of the local program: %s", p["nagios"])
	}
}

func TestAgentRestartKeepsIdentity(t *testing.T) {
	var registered []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			AgentID string `json:"agent_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		registered = append(registered, b.AgentID)
		id := b.AgentID
		if id == "" {
			id = "agt_first"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": id})
	}))
	defer srv.Close()
	dir := t.TempDir()
	f := NewFleet(srv.URL, "wti_x_y")
	first, err := EnsureRegistered(context.Background(), f, dir, hostInfo(nil))
	if err != nil || first.AgentID != "agt_first" {
		t.Fatalf("first start: %v %+v", err, first)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err != nil {
		t.Fatal(err)
	}
	second, err := EnsureRegistered(context.Background(), NewFleet(srv.URL, "wti_x_y"), dir, hostInfo(nil))
	if err != nil || second != first {
		t.Fatalf("restart must keep the id: %v %+v", err, second)
	}
	if len(registered) != 2 || registered[0] != "" || registered[1] != "agt_first" {
		t.Fatalf("the restart must present the stored id: %v", registered)
	}
}

func TestEndpointMustBeHTTPSOrLoopback(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://ingest.example.com": true, "http://localhost:4318": true, "http://127.0.0.1:1": true,
		"http://ingest.example.com": false, "ftp://x": false, "": false,
	} {
		if err := checkEndpoint(url, false); (err == nil) != ok {
			t.Errorf("%q: err=%v, want ok=%v", url, err, ok)
		}
	}
}

func TestOTLPExportsGaugesAndSums(t *testing.T) {
	var got colmetrics.ExportMetricsServiceRequest
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = proto.Unmarshal(b, &got)
	}))
	defer srv.Close()
	o := NewOTLP(srv.URL, "wti_t_s", map[string]string{"host.name": "h"})
	now := time.Now()
	o.Gauge("g", "s", 1.5, map[string]string{"a": "b"}, now)
	o.Sum("c", "", 7, nil, now)
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer wti_t_s" || path != "/v1/metrics" {
		t.Fatalf("auth=%q path=%q", auth, path)
	}
	ms := got.ResourceMetrics[0].ScopeMetrics[0].Metrics
	if len(ms) != 2 || ms[0].GetGauge().DataPoints[0].GetAsDouble() != 1.5 || !ms[1].GetSum().IsMonotonic {
		t.Fatalf("metrics: %v", ms)
	}
	if o.pending() != 0 {
		t.Fatal("a sent batch must be cleared")
	}
}

func TestOTLPRequeuesOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	o := NewOTLP(srv.URL, "wti_t_s", nil)
	o.Gauge("g", "", 1, nil, time.Now())
	if err := o.Flush(context.Background()); err == nil || o.pending() != 1 {
		t.Fatalf("a 503 keeps the batch: err=%v pending=%d", err, o.pending())
	}
}

func TestLoadLocalConfigYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.yaml")
	y := "endpoint: https://gw.example.com:4318\nlabels: {role: db}\nplugin_dir: /opt/wt-agent/plugins\nmodules:\n  nagios:\n    checks:\n      - {plugin: check_disk, args: [\"-w\", \"10%\"]}\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadLocal(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.FleetEndpoint != c.Endpoint || c.Labels["role"] != "db" || !strings.Contains(string(c.Modules["nagios"]), "check_disk") {
		t.Fatalf("%+v", c)
	}
}

func TestLoadLocalFromEnvReplacesFile(t *testing.T) {
	t.Setenv("WT_AGENT_CONFIG_YAML", "endpoint: https://gw.example.com:4318\nmodules:\n  host: {processes: false}\n")
	c, err := LoadLocal(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://gw.example.com:4318" || !strings.Contains(string(c.Modules["host"]), "processes") {
		t.Fatalf("%+v", c)
	}
}
