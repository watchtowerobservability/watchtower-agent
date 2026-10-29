package cloud

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

const cloudSQLScope = "https://www.googleapis.com/auth/sqlservice.admin"

type cloudSQLConfig struct {
	Project        string `json:"project"`
	Endpoint       string `json:"endpoint"` // override (tests)
	ServiceAccount struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	} `json:"service_account"`
}

type cloudSQLList struct {
	Items []struct {
		Name            string `json:"name"`
		State           string `json:"state"`
		Region          string `json:"region"`
		DatabaseVersion string `json:"databaseVersion"`
		Settings        struct {
			UserLabels map[string]string `json:"userLabels"`
		} `json:"settings"`
	} `json:"items"`
	NextPageToken string `json:"nextPageToken"`
}

// cloudSQLSystem maps POSTGRES_15 / MYSQL_8_0 / SQLSERVER_2019_STANDARD to db.system.
func cloudSQLSystem(v string) string {
	switch {
	case strings.HasPrefix(v, "POSTGRES"):
		return "postgresql"
	case strings.HasPrefix(v, "MYSQL"):
		return "mysql"
	case strings.HasPrefix(v, "SQLSERVER"):
		return "mssql"
	}
	return strings.ToLower(v)
}

func (c *cloudSQLConfig) discover(ctx context.Context) ([]Entity, error) {
	if c.Project == "" || c.ServiceAccount.ClientEmail == "" {
		return nil, errors.New("cloud sql config: project and service_account are required")
	}
	key, err := parseRSAKey(c.ServiceAccount.PrivateKey)
	if err != nil {
		return nil, err
	}
	ep, tokenURI := c.Endpoint, c.ServiceAccount.TokenURI
	if ep == "" {
		ep = "https://sqladmin.googleapis.com"
	}
	if tokenURI == "" {
		tokenURI = gcpTokenURI
	}
	cl := httpClient()
	jwt, err := gcpJWTScope(key, c.ServiceAccount.ClientEmail, tokenURI, cloudSQLScope, time.Now())
	if err != nil {
		return nil, err
	}
	tok, _, err := tokenForm(ctx, cl, tokenURI, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt},
	})
	if err != nil {
		return nil, err
	}
	var out []Entity
	page := ""
	for range maxDBPages {
		u := ep + "/v1/projects/" + url.PathEscape(c.Project) + "/instances"
		if page != "" {
			u += "?pageToken=" + url.QueryEscape(page)
		}
		var l cloudSQLList
		if err := doJSON(ctx, cl, "GET", u, map[string]string{"Authorization": "Bearer " + tok}, nil, &l); err != nil {
			return nil, err
		}
		for _, i := range l.Items {
			if i.State == "SUSPENDED" || i.State == "PENDING_DELETE" || i.State == "FAILED" {
				continue
			}
			sys := cloudSQLSystem(i.DatabaseVersion)
			out = append(out, dbEntity("gcp", i.Region, "projects/"+c.Project+"/instances/"+i.Name, "gcp_cloudsql",
				i.Name, sys, sys, i.DatabaseVersion, i.Settings.UserLabels))
		}
		if page = l.NextPageToken; page == "" {
			break
		}
	}
	return out, nil
}
