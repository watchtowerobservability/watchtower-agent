package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeCfg(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("WT_FLARE_PW", "s3cr3t-flare")
	cfg := filepath.Join(dir, "agent.yaml")
	body := "endpoint: https://gw.example.com:4318\nstate_dir: " + dir + "\n" + extra + `modules:
  postgres:
    dsn: "postgres://wt:${env:WT_FLARE_PW}@db.internal:5432/app?sslmode=require"
  mysql:
    dsn: "user=wt password=hunter2 host=db2"
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestFlareBundleHasNoSecrets(t *testing.T) {
	cfg := writeCfg(t, "")
	out := filepath.Join(t.TempDir(), "flare.zip")
	if err := flare(context.Background(), cfg, out); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if strings.Contains(string(b), "s3cr3t-flare") || strings.Contains(string(b), "hunter2") {
			t.Fatalf("%s leaks a secret:\n%s", f.Name, b)
		}
	}
	if !names["version.txt"] || !names["explain.txt"] {
		t.Fatalf("bundle entries = %v", names)
	}
}

func TestStatusReportsFailedModuleAndRedacts(t *testing.T) {
	local := &LocalConfig{Endpoint: "https://u:pw@gw.example.com:4318", FleetEndpoint: "https://gw.example.com:4318"}
	health := map[string]ModuleHealth{
		"logs":  {Healthy: true, Status: "running"},
		"mysql": {Healthy: false, Status: "restarting", Restarts: 2, LastError: "dial password=hunter2 refused", Since: time.Unix(0, 0)},
	}
	st := snapshot(health, map[string]float64{"wt_agent_export_batches_sent_total": 3}, "agt_1", local)
	if len(st.Modules) != 2 || st.Modules[0].Name != "logs" || st.Modules[1].Healthy {
		t.Fatalf("modules = %+v", st.Modules)
	}
	h := httptest.NewServer(statusHandlerFor(func() agentStatus { return st }))
	defer h.Close()
	for _, p := range []string{"/status.json", "/"} {
		resp, err := http.Get(h.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "pw@") {
			t.Fatalf("%s leaks a secret: %s", p, b)
		}
		if !strings.Contains(string(b), "restarting") {
			t.Fatalf("%s lacks the failed module: %s", p, b)
		}
	}
	var got agentStatus
	resp, _ := http.Get(h.URL + "/status.json")
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || got.AgentID != "agt_1" {
		t.Fatalf("json: %v %+v", err, got)
	}
}

func TestStatusListenMustBeLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{"": true, "127.0.0.1:2850": true, "localhost:1": true, "[::1]:2850": true, "0.0.0.0:2850": false, "10.0.0.5:80": false, "nope": false} {
		if (checkLoopbackAddr(addr) == nil) != ok {
			t.Errorf("%q: ok=%v", addr, ok)
		}
	}
}

func TestAgentProxyRoutesEgress(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.RequestURI, "http://gw.example.test/") {
			hits.Add(1)
		}
	}))
	defer proxy.Close()
	c, err := proxiedClient(context.Background(), proxy.URL, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get("http://gw.example.test/v1/logs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("request skipped the proxy")
	}
}
