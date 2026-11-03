package ascode_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/ascode/ascodetest"
)

const manifestSrc = `apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: api-health}
spec: {env_id: env_1, kind: http, interval_s: 60, config: {url: "https://example.com/health"}}
---
apiVersion: watchtower.dev/v1
kind: Template
metadata: {name: slack-default}
spec: {channel_kind: slack, body: "{{ .Title }}"}
---
apiVersion: watchtower.dev/v1
kind: Slo
metadata: {name: checkout}
spec: {target: 99.9}
---
apiVersion: watchtower.dev/v1
kind: AlertRule
metadata: {name: errors}
spec: {threshold: 5}
`

const tmplA = `apiVersion: watchtower.dev/v1
kind: Template
metadata: {name: a}
spec: {channel_kind: slack, body: "1"}
`

const tmplB = `---
apiVersion: watchtower.dev/v1
kind: Template
metadata: {name: b}
spec: {channel_kind: slack, body: "2"}
`

func client(t *testing.T) (*ascode.Client, *ascodetest.Server) {
	t.Helper()
	srv := ascodetest.New(t)
	c, err := ascode.New(srv.URL, "test-key", ascodetest.Project, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func parse(t *testing.T, src string) *ascode.Manifest {
	t.Helper()
	m, err := ascode.ParseManifest([]byte(src), "o/r", "watchtower.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManifestParsesAllKinds(t *testing.T) {
	m := parse(t, manifestSrc)
	for _, k := range []string{"Monitor", "Template", "Slo", "AlertRule"} {
		if !m.Kinds()[k] {
			t.Fatalf("kind %s missing", k)
		}
	}
	want := "manifest:o/r@watchtower.yaml"
	for _, d := range m.Docs {
		if d.Metadata.Labels[ascode.ManagedByKey] != want {
			t.Fatalf("%s/%s label = %v", d.Kind, d.Metadata.Name, d.Metadata.Labels)
		}
	}
}

func TestManifestRejectsUnknownField(t *testing.T) {
	bad := strings.Replace(manifestSrc, "spec:", "specc:", 1)
	if _, err := ascode.ParseManifest([]byte(bad), "o/r", "watchtower.yaml"); err == nil {
		t.Fatal("unknown top-level field accepted")
	}
}

func TestPlanReportsCreateUpdateOrphan(t *testing.T) {
	c, _ := client(t)
	ctx := context.Background()
	live := parse(t, tmplA+tmplB)
	plan, err := c.PlanManifest(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, plan, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := parse(t, strings.Replace(tmplA, `body: "1"`, `body: "new"`, 1)+
		strings.NewReplacer("name: b", "name: fresh").Replace(tmplB))
	plan, err = c.PlanManifest(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range ascode.Drifts(plan) {
		got[d.Key] = d.Op
	}
	if got["a"] != ascode.DriftUpdate || got["fresh"] != ascode.DriftCreate || got["b"] != ascode.DriftOrphan {
		t.Fatalf("drift = %v", got)
	}
}

func TestOrphanNeverDeleted(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	two := parse(t, tmplA+tmplB)
	plan, _ := c.PlanManifest(ctx, two)
	if _, err := c.ApplyManifest(ctx, two, plan, io.Discard); err != nil {
		t.Fatal(err)
	}
	one := parse(t, tmplA)
	plan, err := c.PlanManifest(ctx, one)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyManifest(ctx, one, plan, io.Discard); err != nil {
		t.Fatal(err)
	}
	if srv.Count("Template") != 2 {
		t.Fatalf("orphan deleted: %d templates", srv.Count("Template"))
	}
}

func TestApplyOnlyKindsInFile(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	plan, _ := c.PlanManifest(ctx, parse(t, manifestSrc))
	if _, err := c.ApplyManifest(ctx, parse(t, tmplA), plan, io.Discard); err == nil {
		t.Fatal("a plan with kinds outside the file was applied")
	}
	if srv.Writes() != 0 {
		t.Fatalf("%d writes before refusal", srv.Writes())
	}
}

func TestDriftDetectedAfterUiEdit(t *testing.T) {
	c, _ := client(t)
	ctx := context.Background()
	m := parse(t, manifestSrc)
	plan, _ := c.PlanManifest(ctx, m)
	if _, err := c.ApplyManifest(ctx, m, plan, io.Discard); err != nil {
		t.Fatal(err)
	}
	plan, _ = c.PlanManifest(ctx, m)
	if d := ascode.Drifts(plan); len(d) != 0 {
		t.Fatalf("drift right after apply: %v", d)
	}
	edited := parse(t, strings.Replace(manifestSrc, "interval_s: 60", "interval_s: 5", 1))
	plan, _ = c.PlanManifest(ctx, edited)
	if _, err := c.Apply(ctx, plan, false, io.Discard); err != nil { // the "UI edit"
		t.Fatal(err)
	}
	plan, _ = c.PlanManifest(ctx, m)
	d := ascode.Drifts(plan)
	if len(d) != 1 || d[0].Kind != "Monitor" || d[0].Op != ascode.DriftUpdate {
		t.Fatalf("drift = %v", d)
	}
}

func TestEveryRequestSaysWhoManages(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-WT-Managed-By")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, err := ascode.New(srv.URL, "k", "p", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.ManagedBy = "terraform"
	if err := c.Do(t.Context(), http.MethodPut, "receivers/r", nil, map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	if got != "terraform" {
		t.Fatalf("header %q", got)
	}
}

func TestAlertingKindsAreManaged(t *testing.T) {
	for _, n := range []string{"TimeInterval", "InhibitRule"} {
		if ascode.ByKind(n) == nil {
			t.Fatalf("no kind %s", n)
		}
	}
}
