package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/agent/autoinst"
	"github.com/watchtowerobservability/watchtower-agent/internal/relsig"
)

type reports struct {
	mu  sync.Mutex
	got []map[string]any
}

func (r *reports) handler(extra http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v1/sdk-upgrades/report" {
			b, _ := io.ReadAll(req.Body)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			r.mu.Lock()
			r.got = append(r.got, m)
			r.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		extra(w, req)
	})
}

func TestApplySDKTargetsReportsPerTargetAndSkipsForeignServices(t *testing.T) {
	r := &reports{}
	srv := httptest.NewServer(r.handler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	old := upgradeFn
	t.Cleanup(func() { upgradeFn = old })
	upgradeFn = func(_ context.Context, _ autoinst.Config, _, svc, _ string, _ bool) error {
		if svc == "bad" {
			return errors.New("the switch failed")
		}
		return nil
	}
	dir := t.TempDir()
	cfg := autoinst.Config{Enabled: true, AgentsDir: dir, Rules: []autoinst.Rule{
		{Exe: "a", Lang: "java", Service: "good"}, {Exe: "b", Lang: "java", Service: "bad"}}}
	for _, v := range []string{"2", "9"} { // installed: no download
		mustMkdir(t, dir+"/versions/"+v+"/java")
	}
	e := sdkEnv{f: NewFleet(srv.URL, "wti_x_y"), agent: "agt1"}
	applySDKTargets(context.Background(), e, cfg, []sdkTarget{
		{ID: "t1", Service: "good", Language: "java", Version: "2"},
		{ID: "t2", Service: "bad", Language: "java", Version: "9"},
		{ID: "t3", Service: "elsewhere", Language: "java", Version: "2"},
	})
	want := [][2]string{{"t1", "applying"}, {"t1", "done"}, {"t2", "applying"}, {"t2", "failed"}}
	if len(r.got) != len(want) {
		t.Fatalf("reports %v", r.got)
	}
	for i, w := range want {
		if r.got[i]["id"] != w[0] || r.got[i]["status"] != w[1] || r.got[i]["kind"] != "host" || r.got[i]["agent"] != "agt1" {
			t.Fatalf("report %d = %v, want %v", i, r.got[i], w)
		}
	}
	if r.got[3]["error"] == "" {
		t.Fatal("a failed target carries its error")
	}
}

func bundle(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "javaagent.jar", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("jar"))
	_ = tw.Close()
	_ = zw.Close()
	return b.Bytes()
}

func TestMissingVersionIsDownloadedVerifiedAndInstalled(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data := bundle(t)
	sum := sha256.Sum256(data)
	sign := func(version string, k ed25519.PrivateKey) string {
		return hex.EncodeToString(relsig.Sign(k, "autoinst-java@"+version, runtime.GOOS, runtime.GOARCH, sum[:]))
	}
	dl := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) }))
	defer dl.Close()
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	sigFor := map[string]string{"2.1.0": sign("2.1.0", priv), "3.0.0": sign("3.0.0", otherPriv)}
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("version")
		if sigFor[v] == "" {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"url": dl.URL, "sha256": hex.EncodeToString(sum[:]), "signature": sigFor[v]})
	}))
	defer edge.Close()
	f := NewFleet(edge.URL, "wti_x_y")
	cfg := autoinst.Config{AgentsDir: t.TempDir()}
	ctx := context.Background()

	if err := fetchBundle(ctx, f, dl.Client(), pub, cfg, "java", "2.1.0"); err != nil {
		t.Fatal(err)
	}
	if !autoinst.Installed(cfg, "java", "2.1.0") {
		t.Fatal("not installed after a verified download")
	}
	for _, tc := range []struct{ version, want string }{
		{"3.0.0", "does not verify"}, // signed by another key
		{"4.0.0", "no signed bundle"},
	} {
		err := fetchBundle(ctx, f, dl.Client(), pub, cfg, "java", tc.version)
		if err == nil || !strings.Contains(err.Error(), tc.want) || autoinst.Installed(cfg, "java", tc.version) {
			t.Fatalf("%s: %v", tc.version, err)
		}
	}
	if err := fetchBundle(ctx, f, dl.Client(), nil, cfg, "java", "2.1.0"); err == nil || !strings.Contains(err.Error(), "release key") {
		t.Fatalf("no key: %v", err)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}
