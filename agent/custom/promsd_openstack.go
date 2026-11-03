package custom

// openstack_sd (CFT-A02): Keystone v3 password auth, then Nova `servers/detail` of the project;
// one target per ACTIVE server on its first private (fixed) address, floating with `public`.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

func (c SDConfig) keystone(ctx context.Context, hc *http.Client) (token, compute string, err error) {
	var body struct {
		Auth struct {
			Identity struct {
				Methods  []string `json:"methods"`
				Password struct {
					User struct {
						Name     string            `json:"name"`
						Password string            `json:"password"`
						Domain   map[string]string `json:"domain"`
					} `json:"user"`
				} `json:"password"`
			} `json:"identity"`
			Scope struct {
				Project struct {
					Name   string            `json:"name"`
					Domain map[string]string `json:"domain"`
				} `json:"project"`
			} `json:"scope"`
		} `json:"auth"`
	}
	dom := c.DomainName
	if dom == "" {
		dom = "Default"
	}
	body.Auth.Identity.Methods = []string{"password"}
	u := &body.Auth.Identity.Password.User
	u.Name, u.Password, u.Domain = c.Username, c.Password, map[string]string{"name": dom}
	body.Auth.Scope.Project.Name, body.Auth.Scope.Project.Domain = c.Project, map[string]string{"name": dom}
	b, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/auth/tokens", bytes.NewReader(b))
	if err != nil {
		return "", "", errors.New("sd openstack: bad identity url")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", errors.New("sd openstack: keystone unreachable")
	}
	defer resp.Body.Close()
	var cat struct {
		Token struct {
			Catalog []struct {
				Type      string `json:"type"`
				Endpoints []struct {
					Interface, URL, Region string
				} `json:"endpoints"`
			} `json:"catalog"`
		} `json:"token"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, sdMaxBody))
	token = resp.Header.Get("X-Subject-Token")
	if resp.StatusCode != http.StatusCreated || token == "" || json.Unmarshal(raw, &cat) != nil {
		return "", "", errors.New("sd openstack: keystone refused the credentials")
	}
	for _, s := range cat.Token.Catalog {
		for _, e := range s.Endpoints {
			if s.Type == "compute" && e.Interface == "public" && (c.Region == "" || e.Region == c.Region) {
				return token, strings.TrimSuffix(e.URL, "/"), nil
			}
		}
	}
	return "", "", errors.New("sd openstack: no compute endpoint in the catalog")
}

func (c SDConfig) openstackSD(ctx context.Context, hc *http.Client) ([]TargetSpec, error) {
	tok, compute, err := c.keystone(ctx, hc)
	if err != nil {
		return nil, err
	}
	var res struct {
		Servers []struct {
			ID        string                      `json:"id"`
			Name      string                      `json:"name"`
			Status    string                      `json:"status"`
			Metadata  map[string]string           `json:"metadata"`
			Addresses map[string][]map[string]any `json:"addresses"`
		} `json:"servers"`
	}
	if err := doJSON(ctx, hc, http.MethodGet, compute+"/servers/detail", map[string]string{"X-Auth-Token": tok}, nil, &res); err != nil {
		return nil, err
	}
	port := c.Port
	if port <= 0 {
		port = 9100
	}
	var out []TargetSpec
	for _, s := range res.Servers {
		if s.Status != "ACTIVE" {
			continue
		}
		var ips []string
		var pub []bool
		for _, addrs := range s.Addresses {
			for _, a := range addrs {
				ip, _ := a["addr"].(string)
				kind, _ := a["OS-EXT-IPS:type"].(string)
				ips, pub = append(ips, ip), append(pub, kind == "floating")
			}
		}
		ip := pickIP(ips, pub, c.Public)
		if ip == "" {
			continue
		}
		l := map[string]string{"openstack_instance_id": s.ID, "openstack_instance_name": s.Name, "openstack_project": c.Project}
		for k, v := range s.Metadata {
			l["openstack_tag_"+metaName(k)] = v
		}
		out = append(out, TargetSpec{URL: c.scrapeURL(ip, port), Labels: l})
	}
	return out, nil
}
