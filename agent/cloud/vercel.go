package cloud

// Vercel pull: deployments from the REST API (GET /v7/deployments). This uses no metrics API: it
// reports deployment state and build time only. Never run against a real account.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type vercelConfig struct {
	APIToken  string `json:"api_token"`
	ProjectID string `json:"project_id"`
	TeamID    string `json:"team_id"`
	Endpoint  string `json:"endpoint"`
}

type vercelPull struct {
	c  vercelConfig
	cl *http.Client
}

func newVercel(raw json.RawMessage) (puller, error) {
	var c vercelConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("vercel config: malformed")
	}
	if c.APIToken == "" {
		return nil, errors.New("vercel config: api_token is required")
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://api.vercel.com"
	}
	return &vercelPull{c: c, cl: httpClient()}, nil
}

// The public docs' schema says number, their example shows the same fields quoted: json.Number
// reads both.
type vercelDeployment struct {
	Name       string      `json:"name"`
	ProjectID  string      `json:"projectId"`
	ReadyState string      `json:"readyState"`
	Target     string      `json:"target"`
	Created    json.Number `json:"created"`
	BuildingAt json.Number `json:"buildingAt"`
	Ready      json.Number `json:"ready"`
}

const vercelMaxPages = 10

func (v *vercelPull) pull(ctx context.Context, from, to time.Time, e *emitter) error {
	q := url.Values{
		"since": {strconv.FormatInt(from.UnixMilli(), 10)},
		"until": {strconv.FormatInt(to.UnixMilli(), 10)},
		"limit": {"100"},
	}
	if v.c.ProjectID != "" {
		q.Set("projectId", v.c.ProjectID)
	}
	if v.c.TeamID != "" {
		q.Set("teamId", v.c.TeamID)
	}
	// Pages run newest first; pagination.next is the `until` of the next one. Capped at 10 pages.
	var all []vercelDeployment
	hdr := map[string]string{"Authorization": "Bearer " + v.c.APIToken}
	for page := 0; page < vercelMaxPages; page++ {
		var r struct {
			Deployments []vercelDeployment `json:"deployments"`
			Pagination  struct {
				Next json.Number `json:"next"`
			} `json:"pagination"`
		}
		if err := doJSON(ctx, v.cl, "GET", v.c.Endpoint+"/v7/deployments?"+q.Encode(), hdr, nil, &r); err != nil {
			return err
		}
		all = append(all, r.Deployments...)
		next, err := r.Pagination.Next.Int64()
		until, _ := strconv.ParseInt(q.Get("until"), 10, 64)
		if err != nil || next < from.UnixMilli() || next >= until || len(r.Deployments) == 0 {
			break
		}
		q.Set("until", strconv.FormatInt(next, 10))
	}
	for _, d := range all {
		created, err := d.Created.Int64()
		if err != nil {
			continue
		}
		at := time.UnixMilli(created)
		res := map[string]string{"cloud.resource_id": d.ProjectID}
		attrs := map[string]string{"vercel.name": d.Name, "vercel.state": d.ReadyState, "vercel.target": d.Target}
		e.gauge("cloud.vercel.deployment.created", "{deployment}", 1, at, res, attrs)
		start, err1 := d.BuildingAt.Int64()
		ready, err2 := d.Ready.Int64()
		if err1 == nil && err2 == nil && ready >= start {
			e.gauge("cloud.vercel.deployment.build_time", "s", float64(ready-start)/1000, at, res, attrs)
		}
	}
	return nil
}
