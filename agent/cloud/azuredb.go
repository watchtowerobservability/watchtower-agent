package cloud

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

type azureDBConfig struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	SubscriptionID string `json:"subscription_id"`
	LoginEndpoint  string `json:"login_endpoint"`
	Endpoint       string `json:"endpoint"`
}

type armList struct {
	Value []struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		Properties struct {
			Version string `json:"version"`
		} `json:"properties"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

// azureDBKinds are the ARM collections to list: provider path, api-version, db.system.
var azureDBKinds = []struct{ path, api, system string }{
	{"Microsoft.DBforPostgreSQL/flexibleServers", "2023-06-01-preview", "postgresql"},
	{"Microsoft.DBforMySQL/flexibleServers", "2023-06-30", "mysql"},
	{"Microsoft.Sql/servers", "2021-11-01", "mssql"},
}

func (c *azureDBConfig) discover(ctx context.Context) ([]Entity, error) {
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" || c.SubscriptionID == "" {
		return nil, errors.New("azure database config: tenant_id, client_id, client_secret and subscription_id are required")
	}
	ac := azureConfig{TenantID: c.TenantID, ClientID: c.ClientID, ClientSecret: c.ClientSecret, LoginEndpoint: c.LoginEndpoint, Endpoint: c.Endpoint}
	if ac.LoginEndpoint == "" {
		ac.LoginEndpoint = "https://login.microsoftonline.com"
	}
	if ac.Endpoint == "" {
		ac.Endpoint = "https://management.azure.com"
	}
	a := &azurePull{c: ac, cl: httpClient()}
	tok, err := a.token(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	hdr := map[string]string{"Authorization": "Bearer " + tok}
	// list follows nextLink, but only to the configured management host (the link is untrusted).
	list := func(u string) ([]armList, error) {
		var pages []armList
		for range maxDBPages {
			var l armList
			if err := doJSON(ctx, a.cl, "GET", u, hdr, nil, &l); err != nil {
				return nil, err
			}
			pages = append(pages, l)
			if l.NextLink == "" || !strings.HasPrefix(l.NextLink, ac.Endpoint+"/") {
				break
			}
			u = l.NextLink
		}
		return pages, nil
	}
	var out []Entity
	for _, k := range azureDBKinds {
		pages, err := list(ac.Endpoint + "/subscriptions/" + url.PathEscape(c.SubscriptionID) + "/providers/" + k.path + "?api-version=" + k.api)
		if err != nil {
			return nil, err
		}
		for _, p := range pages {
			for _, s := range p.Value {
				if k.system != "mssql" {
					plat := "azure_" + strings.ToLower(strings.ReplaceAll(k.path, "/", "_"))
					out = append(out, dbEntity("azure", s.Location, s.ID, plat, s.Name, k.system, k.system+"-flexible", s.Properties.Version, s.Tags))
					continue
				}
				dbs, err := list(ac.Endpoint + s.ID + "/databases?api-version=" + k.api)
				if err != nil {
					return nil, err
				}
				for _, dp := range dbs {
					for _, d := range dp.Value {
						if strings.EqualFold(d.Name, "master") {
							continue
						}
						out = append(out, dbEntity("azure", d.Location, d.ID, "azure_sql_database", d.Name, "mssql", "azure-sql", s.Properties.Version, d.Tags))
					}
				}
			}
		}
	}
	return out, nil
}
