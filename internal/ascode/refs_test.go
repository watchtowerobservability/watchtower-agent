package ascode_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
	"github.com/watchtowerobservability/watchtower-agent/internal/ascode/ascodetest"
)

// B4: one file set brings up an empty project with references by name; the second run changes nothing.
func bootstrapDocs(t *testing.T, tokenFile string) []ascode.Doc {
	t.Helper()
	docs, err := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: Slo
metadata: {name: availability}
spec: {env: production, objective: 0.995, window_days: 30, sli: {availability: {monitor: readyz}}}
---
apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: readyz}
spec: {env: production, kind: http, interval_s: 60, config: {url: "https://example.com/readyz"}}
---
apiVersion: watchtower.dev/v1
kind: IngestKey
metadata: {name: hermetica-api}
spec: {env: production, scopes: [ingest:traces, ingest:logs], write_token_to: "` + tokenFile + `"}
---
apiVersion: watchtower.dev/v1
kind: Environment
metadata: {name: production}
spec: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

func TestApplyStandsUpAProjectByNameAndSecondRunIsEmpty(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	tokens := filepath.Join(t.TempDir(), "watchtower.env")
	docs := bootstrapDocs(t, tokens)

	plan, err := c.Plan(ctx, docs, false)
	if err != nil {
		t.Fatal(err)
	}
	var shown bytes.Buffer
	if _, err := c.Apply(ctx, plan, false, &shown); err != nil {
		t.Fatal(err)
	}
	env := srv.Body("Environment", "production")
	mon := srv.Body("Monitor", "readyz")
	if env == nil || mon == nil || mon["env_id"] != env["id"] || mon["env"] != nil {
		t.Fatalf("monitor must carry the environment id: env=%v monitor=%v", env, mon)
	}
	slo := srv.Body("Slo", "availability")
	if got := slo["sli"].(map[string]any)["availability"].(map[string]any)["monitor"]; got != mon["id"] || slo["env_id"] != env["id"] {
		t.Fatalf("slo references not resolved: %v", slo)
	}
	key := srv.Body("IngestKey", "hermetica-api")
	if key["env_id"] != env["id"] || key["write_token_to"] != nil || key["env"] != nil {
		t.Fatalf("key body: %v", key)
	}
	b, err := os.ReadFile(tokens)
	if err != nil || !strings.HasPrefix(string(b), "WT_INGESTKEY_HERMETICA_API=wti_once_") {
		t.Fatalf("token file = %q, %v", b, err)
	}
	if st, _ := os.Stat(tokens); st.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", st.Mode())
	}
	if strings.Contains(shown.String(), "wti_once_") {
		t.Fatalf("the token was also printed: %q", shown.String())
	}

	// a new client has no remembered ids: the second plan must resolve them from the live listing
	again, err := ascode.New(srv.URL, "test-key", ascodetest.Project, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = again.Plan(ctx, docs, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := ascode.Count(plan); n != 0 {
		t.Fatalf("second run changes %d resources: %s", n, ascode.Summary(plan))
	}
}

func TestUnknownReferenceIsAnErrorBeforeAnyWrite(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	docs, err := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: readyz}
spec: {env: nowhere, kind: http}
`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.Plan(ctx, docs, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, plan, false, nil); err == nil || !strings.Contains(err.Error(), `no Environment named "nowhere"`) {
		t.Fatalf("err = %v", err)
	}
	if srv.Writes() != 0 {
		t.Fatalf("%d writes", srv.Writes())
	}
}

func TestPruneLeavesKindsListedOnlyForReferences(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	first := bootstrapDocs(t, filepath.Join(t.TempDir(), "k.env"))
	plan, _ := c.Plan(ctx, first, false)
	if _, err := c.Apply(ctx, plan, false, nil); err != nil {
		t.Fatal(err)
	}
	onlySlo, _ := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: Slo
metadata: {name: availability}
spec: {env: production, objective: 0.995, window_days: 30, sli: {availability: {monitor: readyz}}}
`))
	plan, err := c.Plan(ctx, onlySlo, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, plan, false, nil); err != nil {
		t.Fatal(err)
	}
	if srv.Count("Monitor") != 1 || srv.Count("Environment") != 1 {
		t.Fatal("prune deleted a referenced kind that is not in the manifests")
	}
}

const orgSet = `apiVersion: watchtower.dev/v1
kind: ApiKey
metadata: {name: deploy-bot}
spec: {role: member, write_token_to: "%s"}
---
apiVersion: watchtower.dev/v1
kind: Team
metadata: {name: platform}
spec: {}
---
apiVersion: watchtower.dev/v1
kind: CiSource
metadata: {name: org/repo}
spec: {provider: github, write_token_to: "%s"}
---
apiVersion: watchtower.dev/v1
kind: RedactionDetectors
metadata: {name: detectors}
spec: {detectors: [{kind: email, action: mask}]}
---
apiVersion: watchtower.dev/v1
kind: ContactMethod
metadata: {name: oncall-phone}
spec: {kind: sms, address: "+4915112345678"}
---
apiVersion: watchtower.dev/v1
kind: NotificationRule
metadata: {name: audible}
spec: {rules: [{delay_min: 0, contact_method: oncall-phone}]}
`

func TestOrgKeysTeamsCiSourcesDetectorsContactsAndRules(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	dir := t.TempDir()
	keys, ci := filepath.Join(dir, "keys.env"), filepath.Join(dir, "ci.env")
	docs, err := ascode.ParseDocs([]byte(strings.Replace(strings.Replace(orgSet, "%s", keys, 1), "%s", ci, 1)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.Plan(ctx, docs, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, plan, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"ApiKey", "Team", "CiSource", "ContactMethod"} {
		if srv.Count(kind) != 1 {
			t.Fatalf("%s: %d created", kind, srv.Count(kind))
		}
	}
	for path, prefix := range map[string]string{keys: "WT_APIKEY_DEPLOY_BOT=wta_once_", ci: "WT_CISOURCE_ORG_REPO=cs_once_"} {
		if b, _ := os.ReadFile(path); !strings.HasPrefix(string(b), prefix) {
			t.Fatalf("%s = %q, want prefix %s", path, b, prefix)
		}
	}
	again, err := ascode.New(srv.URL, "test-key", ascodetest.Project, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = again.Plan(ctx, docs, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := ascode.Count(plan); n != 0 {
		t.Fatalf("second run changes %d: %s", n, ascode.Summary(plan))
	}
}

func TestPruneDeletesUnlistedEnvironmentsButNotReferencedOnes(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	seed, _ := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: Environment
metadata: {name: production}
spec: {}
---
apiVersion: watchtower.dev/v1
kind: Environment
metadata: {name: staging}
spec: {}
---
apiVersion: watchtower.dev/v1
kind: Environment
metadata: {name: scratch}
spec: {}
`))
	plan, _ := c.Plan(ctx, seed, false)
	if _, err := c.Apply(ctx, plan, false, nil); err != nil {
		t.Fatal(err)
	}
	// production is declared, staging is only referenced by a monitor, scratch is neither
	want, _ := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: Environment
metadata: {name: production}
spec: {}
---
apiVersion: watchtower.dev/v1
kind: Monitor
metadata: {name: readyz}
spec: {env: staging, kind: http}
`))
	plan, err := c.Plan(ctx, want, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, plan, false, nil); err != nil {
		t.Fatal(err)
	}
	if srv.Body("Environment", "scratch") != nil || srv.Body("Environment", "staging") == nil || srv.Body("Environment", "production") == nil {
		t.Fatalf("environments left: %d", srv.Count("Environment"))
	}
}

// Routing: `receiver` names a Receiver at the root and in nested routes; export turns ids back into names.
func TestRoutingReceiversResolveByNameAtAnyDepth(t *testing.T) {
	c, srv := client(t)
	ctx := context.Background()
	docs, err := ascode.ParseDocs([]byte(`apiVersion: watchtower.dev/v1
kind: Receiver
metadata: {name: page}
spec: {kind: webhook, config: {url: "https://example.com/h"}}
---
apiVersion: watchtower.dev/v1
kind: Routing
metadata: {name: routing}
spec: {receiver: page, routes: [{matchers: [], routes: [{receiver: page}]}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.Plan(ctx, docs, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, plan, false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	id, _ := srv.Body("Receiver", "page")["id"].(string)
	live, err := c.Get(ctx, ascode.ByKind("Routing"), "")
	if err != nil {
		t.Fatal(err)
	}
	tree := live.Body
	inner := tree["routes"].([]any)[0].(map[string]any)["routes"].([]any)[0].(map[string]any)
	if id == "" || tree["receiver"] != id || inner["receiver"] != id {
		t.Fatalf("receiver names not resolved to %q: %v", id, tree)
	}
	exp, err := c.Export(ctx, []string{"Routing"})
	if err != nil || len(exp) != 1 {
		t.Fatalf("export: %v %v", exp, err)
	}
	if exp[0].Spec["receiver"] != "page" {
		t.Fatalf("export keeps the id: %v", exp[0].Spec)
	}
}

func TestExportDropsServerOwnedFieldsAndNamesSingletonsByKind(t *testing.T) {
	d := ascode.ExportDoc(ascode.ByKind("AlertRule"), "r", map[string]any{
		"name": "r", "next_eval_at": "x", "groups_truncated": false, "muted_until": nil, "rebuilt_at": "x", "rebuild_error": nil, "query": "q"})
	if len(d.Spec) != 1 || d.Spec["query"] != "q" {
		t.Fatalf("spec = %v", d.Spec)
	}
	if n := ascode.ExportDoc(ascode.ByKind("OrgSso"), "", map[string]any{}).Metadata.Name; n != "orgsso" {
		t.Fatalf("singleton name = %q", n)
	}
}
