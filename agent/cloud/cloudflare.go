package cloud

// Cloudflare pull: GraphQL Analytics for zones (httpRequests1mGroups) and Workers
// (workersInvocationsAdaptive), authenticated with an API token.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type cloudflareConfig struct {
	APIToken  string   `json:"api_token"`
	AccountID string   `json:"account_id"`
	ZoneIDs   []string `json:"zone_ids"`
	Workers   bool     `json:"workers"`
	Endpoint  string   `json:"endpoint"`
}

type cloudflarePull struct {
	c  cloudflareConfig
	cl *http.Client
}

func newCloudflare(raw json.RawMessage) (puller, error) {
	var c cloudflareConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("cloudflare config: malformed")
	}
	if c.APIToken == "" || len(c.ZoneIDs) == 0 && !c.Workers || c.Workers && c.AccountID == "" {
		return nil, errors.New("cloudflare config: api_token and zone_ids (or workers with account_id) are required")
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://api.cloudflare.com/client/v4/graphql"
	}
	return &cloudflarePull{c: c, cl: httpClient()}, nil
}

const (
	cfZoneQuery = `query($z:String!,$s:Time!,$e:Time!){viewer{zones(filter:{zoneTag:$z}){httpRequests1mGroups(limit:1000,filter:{datetime_geq:$s,datetime_lt:$e}){dimensions{datetimeMinute} sum{requests cachedRequests bytes threats}}}}}`
	cfWorkQuery = `query($a:String!,$s:Time!,$e:Time!){viewer{accounts(filter:{accountTag:$a}){workersInvocationsAdaptive(limit:1000,filter:{datetime_geq:$s,datetime_lt:$e}){dimensions{datetimeMinute scriptName} sum{requests errors subrequests}}}}}`
)

type cfGroup struct {
	Dimensions struct {
		Minute     time.Time `json:"datetimeMinute"`
		ScriptName string    `json:"scriptName"`
	} `json:"dimensions"`
	Sum map[string]float64 `json:"sum"`
}

type cfResp struct {
	Errors []json.RawMessage `json:"errors"`
	Data   struct {
		Viewer struct {
			Zones []struct {
				Groups []cfGroup `json:"httpRequests1mGroups"`
			} `json:"zones"`
			Accounts []struct {
				Groups []cfGroup `json:"workersInvocationsAdaptive"`
			} `json:"accounts"`
		} `json:"viewer"`
	} `json:"data"`
}

func (c *cloudflarePull) query(ctx context.Context, q string, vars map[string]string) (*cfResp, error) {
	body, _ := json.Marshal(map[string]any{"query": q, "variables": vars})
	var r cfResp
	err := doJSON(ctx, c.cl, "POST", c.c.Endpoint,
		map[string]string{"Authorization": "Bearer " + c.c.APIToken, "Content-Type": "application/json"},
		bytes.NewReader(body), &r)
	if err == nil && len(r.Errors) > 0 {
		err = errors.New("graphql error") // the messages can echo query text
	}
	return &r, err
}

func (c *cloudflarePull) pull(ctx context.Context, from, to time.Time, e *emitter) error {
	win := map[string]string{"s": from.UTC().Format(time.RFC3339), "e": to.UTC().Format(time.RFC3339)}
	for _, z := range c.c.ZoneIDs {
		r, err := c.query(ctx, cfZoneQuery, map[string]string{"z": z, "s": win["s"], "e": win["e"]})
		if err != nil {
			return err
		}
		for _, zone := range r.Data.Viewer.Zones {
			emitGroups(e, "cloud.cloudflare.zone.", zone.Groups, c.c.AccountID, z, "")
		}
	}
	if c.c.Workers {
		r, err := c.query(ctx, cfWorkQuery, map[string]string{"a": c.c.AccountID, "s": win["s"], "e": win["e"]})
		if err != nil {
			return err
		}
		for _, acc := range r.Data.Viewer.Accounts {
			emitGroups(e, "cloud.cloudflare.workers.", acc.Groups, c.c.AccountID, "", "script")
		}
	}
	return nil
}

func emitGroups(e *emitter, prefix string, gs []cfGroup, account, zone, by string) {
	for i := range gs {
		g := &gs[i]
		id := zone
		if by == "script" {
			id = g.Dimensions.ScriptName
		}
		res := map[string]string{"cloud.account.id": account, "cloud.resource_id": id}
		for k, v := range g.Sum {
			e.gauge(prefix+k, "", v, g.Dimensions.Minute, res, nil)
		}
	}
}
