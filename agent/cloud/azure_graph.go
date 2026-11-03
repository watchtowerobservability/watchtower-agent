package cloud

// Azure Resource Graph discovery (INF-026): one KQL query lists every resource of the given
// subscriptions with its type, location, resource group and tags. Each becomes a
// `cloud.resource.info` entity, and the resources of `discover.resource_types` join the explicit
// `resources` in the Azure Monitor pull, so a new VM is polled without editing the config.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	discoverEvery      = 5 * time.Minute
	azureGraphPage     = 1000
	maxDiscoveredPolls = 500 // metric calls per pull for discovered resources
)

type azureDiscover struct {
	Subscriptions []string `json:"subscriptions"`
	// ResourceTypes are the types whose discovered resources get metric pulls, e.g.
	// microsoft.compute/virtualmachines. Empty means inventory only.
	ResourceTypes []string `json:"resource_types"`
}

var (
	azureSubRE  = regexp.MustCompile(`^[0-9A-Fa-f-]{36}$|^[A-Za-z0-9-]{1,64}$`)
	azureTypeRE = regexp.MustCompile(`^[A-Za-z0-9.]+/[A-Za-z0-9./]+$`)
)

func (d *azureDiscover) check() error {
	if len(d.Subscriptions) == 0 {
		return errors.New("azure config: discover.subscriptions is required")
	}
	for _, s := range d.Subscriptions {
		if !azureSubRE.MatchString(s) {
			return errors.New("azure config: discover.subscriptions must be subscription ids")
		}
	}
	for _, t := range d.ResourceTypes {
		if !azureTypeRE.MatchString(t) { // the types are quoted into the KQL query
			return errors.New("azure config: discover.resource_types must look like microsoft.compute/virtualmachines")
		}
	}
	return nil
}

type azureResource struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Location       string            `json:"location"`
	ResourceGroup  string            `json:"resourceGroup"`
	SubscriptionID string            `json:"subscriptionId"`
	Tags           map[string]string `json:"tags"`
}

// azureInventory caches the discovered resources; a failed walk keeps the last list.
type azureInventory struct {
	mu   sync.Mutex
	list []azureResource
	at   time.Time
}

var azurePlatform = map[string]string{
	"microsoft.compute/virtualmachines":           "azure_vm",
	"microsoft.containerservice/managedclusters":  "azure_aks",
	"microsoft.web/sites":                         "azure_app_service",
	"microsoft.app/containerapps":                 "azure_container_apps",
	"microsoft.containerinstance/containergroups": "azure_container_instances",
}

// graphResources runs the Resource Graph query over all pages (at most maxInventory rows).
func (a *azurePull) graphResources(ctx context.Context, tok string) ([]azureResource, error) {
	q := "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags | order by id asc"
	var out []azureResource
	skip := ""
	for len(out) < maxInventory {
		body := map[string]any{"subscriptions": a.c.Discover.Subscriptions, "query": q,
			"options": map[string]any{"$top": azureGraphPage, "resultFormat": "objectArray"}}
		if skip != "" {
			body["options"].(map[string]any)["$skipToken"] = skip
		}
		var r struct {
			Data      []azureResource `json:"data"`
			SkipToken string          `json:"$skipToken"`
		}
		b, _ := json.Marshal(body)
		u := a.c.Endpoint + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
		err := doJSON(ctx, a.cl, http.MethodPost, u, map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
			bytes.NewReader(b), &r)
		if err != nil {
			return out, err
		}
		out = append(out, r.Data...)
		if skip = r.SkipToken; skip == "" {
			break
		}
	}
	return out, nil
}

// discovered refreshes the inventory every discoverEvery, emitting it, and returns the ARM ids
// to poll metrics for.
func (a *azurePull) discovered(ctx context.Context, tok string, now time.Time, out sink.Sink) ([]string, error) {
	inv := &a.inv
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var err error
	if inv.list == nil || now.Sub(inv.at) >= discoverEvery {
		var rs []azureResource
		rs, err = a.graphResources(ctx, tok)
		if err == nil || len(rs) > 0 {
			inv.list, inv.at = append([]azureResource{}, rs...), now // non-nil: an empty walk is cached too
			emitAzureInventory(out, rs, now)
		}
	}
	want := map[string]bool{}
	for _, t := range a.c.Discover.ResourceTypes {
		want[strings.ToLower(t)] = true
	}
	var ids []string
	for _, r := range inv.list {
		// Joined to the endpoint like a configured id, so it must be a path.
		if want[strings.ToLower(r.Type)] && strings.HasPrefix(r.ID, "/subscriptions/") && len(ids) < maxDiscoveredPolls {
			ids = append(ids, r.ID)
		}
	}
	return ids, err
}

func emitAzureInventory(out sink.Sink, rs []azureResource, at time.Time) {
	for _, r := range rs {
		typ := strings.ToLower(r.Type)
		platform := azurePlatform[typ]
		if platform == "" {
			platform = "azure"
		}
		// cloud.resource_id is the name, as the Azure Monitor series carry it; the ARM id is kept too.
		emitResourceInfo(out, map[string]string{
			"cloud.provider": "azure", "cloud.platform": platform, "cloud.resource_id": r.Name,
			"cloud.region": r.Location, "cloud.account.id": r.SubscriptionID, "cloud.service": typ,
			"cloud.azure.resource_group": r.ResourceGroup, "cloud.azure.arm_id": r.ID,
		}, r.Tags, at)
	}
}

// pollIDs is the explicit resources plus the discovered ones, without duplicates.
func pollIDs(explicit, found []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(explicit)+len(found))
	for _, id := range append(append([]string(nil), explicit...), found...) {
		if k := strings.ToLower(id); !seen[k] {
			seen[k] = true
			out = append(out, id)
		}
	}
	return out
}
