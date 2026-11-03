package cloud

// GCP Cloud Asset Inventory (INF-026): searchAllResources over a project, folder or organization
// lists every asset with its type, location and labels. Each becomes a `cloud.resource.info`
// entity, and with a folder or organization scope the projects the assets live in join the
// configured project in the Cloud Monitoring pull, so a new project is polled without a config edit.

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	gcpAssetEndpoint   = "https://cloudasset.googleapis.com"
	gcpPlatformScope   = "https://www.googleapis.com/auth/cloud-platform"
	gcpAssetPage       = 500
	maxDiscoveredProjs = 50
)

type gcpInventory struct {
	// Scope is projects/<id>, folders/<n> or organizations/<n>; default the pull's project.
	Scope      string   `json:"scope"`
	AssetTypes []string `json:"asset_types"` // e.g. compute.googleapis.com/Instance; empty means all
}

var (
	gcpScopeRE = regexp.MustCompile(`^(projects|folders|organizations)/[A-Za-z0-9_.:-]{1,64}$`)
	gcpTypeRE  = regexp.MustCompile(`^[a-z0-9.-]+\.googleapis\.com/[A-Za-z0-9]+$`)
)

func (inv *gcpInventory) check(project string) error {
	if inv.Scope == "" {
		inv.Scope = "projects/" + project
	}
	if !gcpScopeRE.MatchString(inv.Scope) { // joined into the request path
		return errors.New("gcp config: inventory.scope must be projects/<id>, folders/<n> or organizations/<n>")
	}
	for _, t := range inv.AssetTypes {
		if !gcpTypeRE.MatchString(t) {
			return errors.New("gcp config: inventory.asset_types must look like compute.googleapis.com/Instance")
		}
	}
	return nil
}

type gcpAsset struct {
	Name        string            `json:"name"`
	AssetType   string            `json:"assetType"`
	Project     string            `json:"project"` // projects/<number>
	DisplayName string            `json:"displayName"`
	Location    string            `json:"location"`
	Labels      map[string]string `json:"labels"`
	State       string            `json:"state"`
}

// gcpAssetCache keeps the last walk; a failed walk keeps the previous list.
type gcpAssetCache struct {
	mu   sync.Mutex
	list []gcpAsset
	at   time.Time
	tok  tokenCache // cloud-platform scope, which the Asset API needs
}

var gcpPlatform = map[string]string{
	"compute.googleapis.com/Instance":        "gcp_compute_engine",
	"run.googleapis.com/Service":             "gcp_cloud_run",
	"cloudfunctions.googleapis.com/Function": "gcp_cloud_functions",
	"container.googleapis.com/Cluster":       "gcp_kubernetes_engine",
	"appengine.googleapis.com/Application":   "gcp_app_engine",
}

func (g *gcpPull) assetToken(ctx context.Context, now time.Time) (string, error) {
	return g.assets.tok.get(now, func() (string, time.Duration, error) {
		jwt, err := gcpJWTScope(g.key, g.c.ServiceAccount.ClientEmail, g.c.ServiceAccount.TokenURI, gcpPlatformScope, now)
		if err != nil {
			return "", 0, err
		}
		return tokenForm(ctx, g.cl, g.c.ServiceAccount.TokenURI, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt},
		})
	})
}

func (g *gcpPull) searchAssets(ctx context.Context, now time.Time) ([]gcpAsset, error) {
	tok, err := g.assetToken(ctx, now)
	if err != nil {
		return nil, err
	}
	base := gcpAssetEndpoint
	if g.c.Endpoint != gcpEndpoint {
		base = g.c.Endpoint // the same override as Monitoring (tests, private service connect)
	}
	var out []gcpAsset
	page := ""
	for len(out) < maxInventory {
		q := url.Values{"pageSize": {strconv.Itoa(gcpAssetPage)}, "assetTypes": g.c.Inventory.AssetTypes}
		if page != "" {
			q.Set("pageToken", page)
		}
		var r struct {
			Results       []gcpAsset `json:"results"`
			NextPageToken string     `json:"nextPageToken"`
		}
		u := base + "/v1/" + g.c.Inventory.Scope + ":searchAllResources?" + q.Encode()
		if err := doJSON(ctx, g.cl, "GET", u, map[string]string{"Authorization": "Bearer " + tok}, nil, &r); err != nil {
			return out, err
		}
		out = append(out, r.Results...)
		if page = r.NextPageToken; page == "" {
			break
		}
	}
	return out, nil
}

// discovered refreshes and emits the inventory every discoverEvery and returns the projects to
// pull metrics for: the configured one plus, for a folder or organization scope, every project
// an asset lives in.
func (g *gcpPull) discovered(ctx context.Context, now time.Time, out sink.Sink) ([]string, error) {
	c := &g.assets
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if c.list == nil || now.Sub(c.at) >= discoverEvery {
		var as []gcpAsset
		as, err = g.searchAssets(ctx, now)
		if err == nil || len(as) > 0 {
			c.list, c.at = append([]gcpAsset{}, as...), now // non-nil: an empty walk is cached too
			g.emitAssets(out, as, now)
		}
	}
	projects := []string{g.c.Project}
	if strings.HasPrefix(g.c.Inventory.Scope, "projects/") {
		return projects, err
	}
	set := map[string]bool{}
	for _, a := range c.list {
		if p, ok := strings.CutPrefix(a.Project, "projects/"); ok && p != "" && p != g.c.Project {
			set[p] = true
		}
	}
	more := make([]string, 0, len(set))
	for p := range set {
		more = append(more, p)
	}
	sort.Strings(more)
	return append(projects, more[:min(len(more), maxDiscoveredProjs)]...), err
}

func (g *gcpPull) emitAssets(out sink.Sink, as []gcpAsset, at time.Time) {
	for _, a := range as {
		platform := gcpPlatform[a.AssetType]
		if platform == "" {
			platform = "gcp"
		}
		id := a.DisplayName
		if id == "" {
			id = a.Name[strings.LastIndex(a.Name, "/")+1:]
		}
		account := g.c.Project
		if !strings.HasPrefix(g.c.Inventory.Scope, "projects/") {
			account = strings.TrimPrefix(a.Project, "projects/")
		}
		emitResourceInfo(out, map[string]string{
			"cloud.provider": "gcp", "cloud.platform": platform, "cloud.resource_id": id,
			"cloud.region": a.Location, "cloud.account.id": account, "cloud.service": a.AssetType,
			"cloud.gcp.asset_name": a.Name, "cloud.gcp.state": a.State,
		}, a.Labels, at)
	}
}
