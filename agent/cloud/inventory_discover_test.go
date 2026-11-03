package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func infoByID(rec *sink.Recorder) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, s := range rec.Snapshot() {
		if s.Name == "cloud.resource.info" {
			out[s.Attrs["resource.cloud.resource_id"]] = s.Attrs
		}
	}
	return out
}

// Resource Graph pages through the subscriptions; every resource becomes an entity with its tags,
// the virtual machines join the explicit id in the metric pull (once each), and a discovered
// resource whose metric call fails does not stop the others.
func TestAzureResourceGraphFeedsInventoryAndPulls(t *testing.T) {
	const vm1 = "/subscriptions/sub1/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/vm1"
	const vm2 = "/subscriptions/sub1/resourceGroups/g/providers/Microsoft.Compute/virtualMachines/vm2"
	const vm3 = "/subscriptions/sub1/resourceGroups/h/providers/Microsoft.Compute/virtualMachines/vm3"
	var mu sync.Mutex
	polled := map[string]int{}
	graphCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			fmt.Fprint(w, `{"access_token":"az1","expires_in":3600}`)
		case r.URL.Path == "/providers/Microsoft.ResourceGraph/resources":
			graphCalls++
			var b struct {
				Subscriptions []string       `json:"subscriptions"`
				Query         string         `json:"query"`
				Options       map[string]any `json:"options"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Header.Get("Authorization") != "Bearer az1" || len(b.Subscriptions) != 1 || b.Subscriptions[0] != "sub1" ||
				!strings.HasPrefix(b.Query, "Resources") {
				w.WriteHeader(400)
				return
			}
			if b.Options["$skipToken"] == nil {
				fmt.Fprintf(w, `{"data":[{"id":%q,"name":"vm2","type":"Microsoft.Compute/virtualMachines","location":"westeurope","resourceGroup":"g",
					"subscriptionId":"sub1","tags":{"team":"core"}},{"id":"/subscriptions/sub1/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/st1",
					"name":"st1","type":"microsoft.storage/storageaccounts","location":"westeurope","resourceGroup":"g","subscriptionId":"sub1","tags":null}],
					"$skipToken":"p2"}`, vm2)
				return
			}
			fmt.Fprintf(w, `{"data":[{"id":%q,"name":"vm1","type":"microsoft.compute/virtualmachines","location":"westeurope","resourceGroup":"g","subscriptionId":"sub1"},
				{"id":%q,"name":"vm3","type":"microsoft.compute/virtualmachines","location":"northeurope","resourceGroup":"h","subscriptionId":"sub1"}]}`, vm1, vm3)
		case strings.HasSuffix(r.URL.Path, "/providers/microsoft.insights/metrics"):
			id := strings.TrimSuffix(r.URL.Path, "/providers/microsoft.insights/metrics")
			polled[id]++
			if id == vm3 {
				w.WriteHeader(400) // e.g. a deallocated VM
				return
			}
			fmt.Fprint(w, `{"value":[{"name":{"value":"Percentage CPU"},"unit":"Percent","timeseries":[{"data":[{"timeStamp":"2026-10-30T10:00:00Z","average":5}]}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"tenant_id":"t1","client_id":"c1","client_secret":"shh","metrics":["Percentage CPU"],"resources":[%q],
		"discover":{"subscriptions":["sub1"],"resource_types":["microsoft.compute/virtualmachines"]},
		"login_endpoint":%q,"endpoint":%q}`, vm1, srv.URL, srv.URL)
	p, err := newAzure(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	em := newEmitter(rec, "azure")
	now := time.Now()
	for i := range 2 { // the second pull reuses the cached inventory
		if err := p.pull(context.Background(), now.Add(-time.Hour), now.Add(time.Duration(i)*time.Minute), em); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if graphCalls != 2 || polled[vm1] != 2 || polled[vm2] != 2 || polled[vm3] != 2 || len(polled) != 3 {
		t.Fatalf("graph calls %d, polled %v", graphCalls, polled)
	}
	info := infoByID(rec)
	if len(info) != 4 || info["vm2"]["resource.cloud.tag.team"] != "core" || info["vm2"]["resource.cloud.platform"] != "azure_vm" ||
		info["vm2"]["resource.cloud.azure.arm_id"] != vm2 || info["st1"]["resource.cloud.service"] != "microsoft.storage/storageaccounts" ||
		info["vm3"]["resource.cloud.region"] != "northeurope" || info["vm1"]["resource.host.id"] != "" {
		t.Fatalf("inventory: %v", info)
	}
	cpu := 0
	for _, s := range rec.Snapshot() {
		if s.Name == "cloud.azure.microsoft.compute.virtualmachines.percentage_cpu" {
			cpu++
		}
	}
	if cpu != 2 { // vm1 and vm2, deduplicated across the overlapping second pull
		t.Fatalf("cpu points: %d", cpu)
	}
}

func TestAzureDiscoverConfigChecks(t *testing.T) {
	base := `{"tenant_id":"t","client_id":"c","client_secret":"s",%s}`
	for _, bad := range []string{
		`"discover":{"subscriptions":[]}`,
		`"discover":{"subscriptions":["s/../x"]}`,
		`"discover":{"subscriptions":["sub1"],"resource_types":["x') | union (y"]}`,
		`"discover":{"subscriptions":["sub1"],"resource_types":["microsoft.compute/virtualmachines"]}`, // no metrics
	} {
		if _, err := newAzure(json.RawMessage(fmt.Sprintf(base, bad))); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := newAzure(json.RawMessage(fmt.Sprintf(base, `"discover":{"subscriptions":["sub1"]}`))); err != nil {
		t.Fatalf("inventory only must be accepted: %v", err)
	}
}

// An organization scope lists assets with labels under the cloud-platform scope, and the projects
// the assets live in join the configured project in the Monitoring pull.
func TestGcpAssetInventoryFeedsEntitiesAndProjects(t *testing.T) {
	_, pemKey := testKeyPEM(t)
	var mu sync.Mutex
	series := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/token":
			_ = r.ParseForm()
			parts := strings.Split(r.Form.Get("assertion"), ".")
			claims, _ := base64.RawURLEncoding.DecodeString(parts[min(1, len(parts)-1)])
			if strings.Contains(string(claims), gcpPlatformScope) {
				fmt.Fprint(w, `{"access_token":"asset-tok","expires_in":3600}`)
				return
			}
			fmt.Fprint(w, `{"access_token":"mon-tok","expires_in":3600}`)
		case r.URL.Path == "/v1/organizations/42:searchAllResources":
			if r.Header.Get("Authorization") != "Bearer asset-tok" || r.URL.Query()["assetTypes"][0] != "compute.googleapis.com/Instance" {
				w.WriteHeader(403)
				return
			}
			if r.URL.Query().Get("pageToken") == "" {
				fmt.Fprint(w, `{"results":[{"name":"//compute.googleapis.com/projects/proj1/zones/us-central1-a/instances/vm1","assetType":"compute.googleapis.com/Instance",
					"project":"projects/111","displayName":"vm1","location":"us-central1-a","labels":{"env":"prod"},"state":"RUNNING"}],"nextPageToken":"n2"}`)
				return
			}
			fmt.Fprint(w, `{"results":[{"name":"//compute.googleapis.com/projects/other/zones/europe-west1-b/instances/vm9","assetType":"compute.googleapis.com/Instance",
				"project":"projects/222","displayName":"vm9","location":"europe-west1-b","state":"TERMINATED"}]}`)
		case strings.HasPrefix(r.URL.Path, "/v3/projects/"):
			if r.Header.Get("Authorization") != "Bearer mon-tok" {
				w.WriteHeader(401)
				return
			}
			series[strings.Split(r.URL.Path, "/")[3]]++
			fmt.Fprint(w, `{"timeSeries":[{"metric":{"type":"compute.googleapis.com/instance/cpu/utilization"},"resource":{"type":"gce_instance","labels":{"instance_id":"1"}},
				"points":[{"interval":{"endTime":"2026-10-30T10:00:00Z"},"value":{"doubleValue":0.5}}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	cfg := fmt.Sprintf(`{"project":"proj1","metrics":["compute.googleapis.com/instance/cpu/utilization"],
		"inventory":{"scope":"organizations/42","asset_types":["compute.googleapis.com/Instance"]},
		"endpoint":%q,"service_account":{"client_email":"sa@p.iam","private_key":%q,"token_uri":%q}}`, srv.URL, pemKey, srv.URL+"/token")
	p, err := newGCP(json.RawMessage(cfg))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	if err := p.pull(context.Background(), time.Now().Add(-time.Hour), time.Now(), newEmitter(rec, "gcp")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if series["proj1"] != 1 || series["111"] != 1 || series["222"] != 1 {
		t.Fatalf("projects polled: %v", series)
	}
	info := infoByID(rec)
	if len(info) != 2 || info["vm1"]["resource.cloud.tag.env"] != "prod" || info["vm1"]["resource.cloud.platform"] != "gcp_compute_engine" ||
		info["vm9"]["resource.cloud.account.id"] != "222" || info["vm9"]["resource.cloud.gcp.state"] != "TERMINATED" {
		t.Fatalf("inventory: %v", info)
	}
	if _, err := newGCP(json.RawMessage(strings.Replace(cfg, "organizations/42", "organizations/42/../x", 1))); err == nil {
		t.Fatal("a scope that is not a plain resource name must be refused")
	}
}
