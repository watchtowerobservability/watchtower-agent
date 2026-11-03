package custom

// Cloud service discovery (CFT-A02): azure, gce, digitalocean, hetzner, linode and openstack.
// Credentials come from the SD config (secret references allowed) or the platform's instance
// identity (Azure managed identity, GCE metadata server). Only running machines are returned;
// the private address is used unless `public: true`.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	azureMgmt = "https://management.azure.com"
	azureIMDS = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
	gceToken  = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

func (c SDConfig) base(def string) string {
	if c.Endpoint != "" {
		return strings.TrimSuffix(c.Endpoint, "/")
	}
	return def
}

func (c SDConfig) azureToken(ctx context.Context, hc *http.Client) (string, error) {
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if c.ClientID != "" && c.ClientSecret != "" && c.TenantID != "" {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ClientID}, "client_secret": {c.ClientSecret},
			"scope": {"https://management.azure.com/.default"}}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.microsoftonline.com/"+url.PathEscape(c.TenantID)+"/oauth2/v2.0/token",
			strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.New("azure token request")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := hc.Do(req)
		if err != nil {
			return "", errors.New("azure token request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&t) != nil || t.AccessToken == "" {
			return "", errors.New("azure token refused")
		}
		return t.AccessToken, nil
	}
	if err := doJSON(ctx, hc, http.MethodGet, azureIMDS, map[string]string{"Metadata": "true"}, nil, &t); err != nil || t.AccessToken == "" {
		return "", errors.New("azure managed identity unavailable")
	}
	return t.AccessToken, nil
}

func (c SDConfig) azureSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	tok, err := c.azureToken(ctx, hc)
	if err != nil {
		return nil, err
	}
	base := c.base(azureMgmt) + "/subscriptions/" + url.PathEscape(c.SubscriptionID)
	if c.ResourceGroup != "" {
		base += "/resourceGroups/" + url.PathEscape(c.ResourceGroup)
	}
	type vm struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		Properties struct {
			HardwareProfile struct {
				VMSize string `json:"vmSize"`
			} `json:"hardwareProfile"`
		} `json:"properties"`
	}
	vms := map[string]vm{}
	for u, n := base+"/providers/Microsoft.Compute/virtualMachines?api-version=2022-08-01", 0; u != "" && n < sdMaxPages; n++ {
		var page struct {
			Value    []vm   `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := doJSON(ctx, hc, http.MethodGet, u, bearer(tok), nil, &page); err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			vms[strings.ToLower(v.ID)] = v
		}
		u = page.NextLink
	}
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	var out []TargetSpec
	for u, n := base+"/providers/Microsoft.Network/networkInterfaces?api-version=2022-07-01", 0; u != "" && n < sdMaxPages; n++ {
		var page struct {
			Value []struct {
				Properties struct {
					VirtualMachine struct {
						ID string `json:"id"`
					} `json:"virtualMachine"`
					IPConfigurations []struct {
						Properties struct {
							PrivateIPAddress string `json:"privateIPAddress"`
						} `json:"properties"`
					} `json:"ipConfigurations"`
				} `json:"properties"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := doJSON(ctx, hc, http.MethodGet, u, bearer(tok), nil, &page); err != nil {
			return nil, err
		}
		for _, nic := range page.Value {
			v, ok := vms[strings.ToLower(nic.Properties.VirtualMachine.ID)]
			if !ok || len(nic.Properties.IPConfigurations) == 0 || nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress == "" {
				continue
			}
			l := map[string]string{"azure_machine_name": v.Name, "azure_location": v.Location, "azure_machine_size": v.Properties.HardwareProfile.VMSize}
			for k, tv := range v.Tags {
				l["azure_tag_"+metaName(k)] = tv
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress, port), Labels: l})
		}
		u = page.NextLink
	}
	return out, nil
}

func (c SDConfig) gceSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	tok := c.Token
	if tok == "" {
		var t struct {
			AccessToken string `json:"access_token"`
		}
		if err := doJSON(ctx, hc, http.MethodGet, gceToken, map[string]string{"Metadata-Flavor": "Google"}, nil, &t); err != nil {
			return nil, errors.New("gce metadata token unavailable")
		}
		tok = t.AccessToken
	}
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	base := c.base("https://compute.googleapis.com") + "/compute/v1/projects/" + url.PathEscape(c.Project) + "/zones/" + url.PathEscape(c.Zone) + "/instances"
	var out []TargetSpec
	page := ""
	for range sdMaxPages {
		q := url.Values{"maxResults": {"500"}}
		if c.Query != "" {
			q.Set("filter", c.Query)
		}
		if page != "" {
			q.Set("pageToken", page)
		}
		var res struct {
			Items []struct {
				Name              string            `json:"name"`
				ID                string            `json:"id"`
				Status            string            `json:"status"`
				MachineType       string            `json:"machineType"`
				Labels            map[string]string `json:"labels"`
				NetworkInterfaces []struct {
					NetworkIP     string `json:"networkIP"`
					AccessConfigs []struct {
						NatIP string `json:"natIP"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
			} `json:"items"`
			Next string `json:"nextPageToken"`
		}
		if err := doJSON(ctx, hc, http.MethodGet, base+"?"+q.Encode(), bearer(tok), nil, &res); err != nil {
			return nil, err
		}
		for _, in := range res.Items {
			if in.Status != "RUNNING" || len(in.NetworkInterfaces) == 0 {
				continue
			}
			ip := in.NetworkInterfaces[0].NetworkIP
			if c.Public && len(in.NetworkInterfaces[0].AccessConfigs) > 0 {
				ip = in.NetworkInterfaces[0].AccessConfigs[0].NatIP
			}
			l := map[string]string{"gce_instance_name": in.Name, "gce_instance_id": in.ID, "gce_zone": c.Zone, "gce_project": c.Project,
				"gce_machine_type": in.MachineType[strings.LastIndex(in.MachineType, "/")+1:]}
			for k, v := range in.Labels {
				l["gce_label_"+metaName(k)] = v
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: l})
		}
		if page = res.Next; page == "" {
			break
		}
	}
	return out, nil
}

func (c SDConfig) digitalOceanSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	var out []TargetSpec
	for u, n := c.base("https://api.digitalocean.com")+"/v2/droplets?per_page=200", 0; u != "" && n < sdMaxPages; n++ {
		var res struct {
			Droplets []struct {
				ID       int      `json:"id"`
				Name     string   `json:"name"`
				Status   string   `json:"status"`
				SizeSlug string   `json:"size_slug"`
				Tags     []string `json:"tags"`
				Region   struct {
					Slug string `json:"slug"`
				} `json:"region"`
				Networks struct {
					V4 []struct {
						IP   string `json:"ip_address"`
						Type string `json:"type"`
					} `json:"v4"`
				} `json:"networks"`
			} `json:"droplets"`
			Links struct {
				Pages struct {
					Next string `json:"next"`
				} `json:"pages"`
			} `json:"links"`
		}
		if err := doJSON(ctx, hc, http.MethodGet, u, bearer(c.Token), nil, &res); err != nil {
			return nil, err
		}
		for _, d := range res.Droplets {
			ips := make([]string, 0, len(d.Networks.V4))
			pub := make([]bool, 0, len(d.Networks.V4))
			for _, a := range d.Networks.V4 {
				ips, pub = append(ips, a.IP), append(pub, a.Type == "public")
			}
			ip := pickIP(ips, pub, c.Public)
			if d.Status != "active" || ip == "" {
				continue
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: map[string]string{"do_droplet_id": strconv.Itoa(d.ID),
				"do_droplet_name": d.Name, "do_region": d.Region.Slug, "do_size": d.SizeSlug, "do_tags": "," + strings.Join(d.Tags, ",") + ","}})
		}
		u = res.Links.Pages.Next
	}
	return out, nil
}

func (c SDConfig) hetznerSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	var out []TargetSpec
	for page := 1; page > 0 && page <= sdMaxPages; {
		var res struct {
			Servers []struct {
				ID        int               `json:"id"`
				Name      string            `json:"name"`
				Status    string            `json:"status"`
				Labels    map[string]string `json:"labels"`
				PublicNet struct {
					IPv4 struct {
						IP string `json:"ip"`
					} `json:"ipv4"`
				} `json:"public_net"`
				PrivateNet []struct {
					IP string `json:"ip"`
				} `json:"private_net"`
				Datacenter struct {
					Name string `json:"name"`
				} `json:"datacenter"`
			} `json:"servers"`
			Meta struct {
				Pagination struct {
					Next int `json:"next_page"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		u := c.base("https://api.hetzner.cloud") + "/v1/servers?per_page=50&page=" + strconv.Itoa(page)
		if err := doJSON(ctx, hc, http.MethodGet, u, bearer(c.Token), nil, &res); err != nil {
			return nil, err
		}
		for _, s := range res.Servers {
			ip := s.PublicNet.IPv4.IP
			if !c.Public && len(s.PrivateNet) > 0 {
				ip = s.PrivateNet[0].IP
			}
			if s.Status != "running" || ip == "" {
				continue
			}
			l := map[string]string{"hetzner_server_id": strconv.Itoa(s.ID), "hetzner_server_name": s.Name, "hetzner_datacenter": s.Datacenter.Name}
			for k, v := range s.Labels {
				l["hetzner_label_"+metaName(k)] = v
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: l})
		}
		page = res.Meta.Pagination.Next
	}
	return out, nil
}

func (c SDConfig) linodeSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	var out []TargetSpec
	for page, pages := 1, 1; page <= pages && page <= sdMaxPages; page++ {
		var res struct {
			Data []struct {
				ID     int      `json:"id"`
				Label  string   `json:"label"`
				Status string   `json:"status"`
				Region string   `json:"region"`
				Type   string   `json:"type"`
				IPv4   []string `json:"ipv4"`
				Tags   []string `json:"tags"`
			} `json:"data"`
			Pages int `json:"pages"`
		}
		u := c.base("https://api.linode.com") + "/v4/linode/instances?page_size=500&page=" + strconv.Itoa(page)
		if err := doJSON(ctx, hc, http.MethodGet, u, bearer(c.Token), nil, &res); err != nil {
			return nil, err
		}
		pages = res.Pages
		for _, l := range res.Data {
			pub := make([]bool, len(l.IPv4))
			for i, a := range l.IPv4 {
				pub[i] = !strings.HasPrefix(a, "192.168.") // Linode private addresses
			}
			ip := pickIP(l.IPv4, pub, c.Public)
			if l.Status != "running" || ip == "" {
				continue
			}
			out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: map[string]string{"linode_id": strconv.Itoa(l.ID),
				"linode_label": l.Label, "linode_region": l.Region, "linode_type": l.Type, "linode_tags": "," + strings.Join(l.Tags, ",") + ","}})
		}
	}
	return out, nil
}

// pickIP returns the first address whose publicness matches wantPublic, else the first one.
func pickIP(ips []string, public []bool, wantPublic bool) string {
	for i, ip := range ips {
		if public[i] == wantPublic {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}
