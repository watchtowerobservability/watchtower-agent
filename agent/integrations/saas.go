package integrations

// Integrations of CFT-A04 (Alloy prometheus.exporter.* parity) that speak a product's own API:
// Elasticsearch, Squid, GitHub, Snowflake and Databricks (dnsmasq is in dnsmasq.go). Tokens
// and URLs are local-file only (a secret reference such as `${file:...}` works).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// TokenConfig is an HTTP API with a bearer-style token (or basic auth via HTTPConfig).
type TokenConfig struct {
	HTTPConfig
	Token string   `json:"token"`
	Repos []string `json:"repos"` // github: owner/name
	// snowflake
	Warehouse string `json:"warehouse"`
}

func (c *TokenConfig) check() error { return c.HTTPConfig.check() }

func doJSON(ctx context.Context, c HTTPConfig, method, url string, hdr map[string]string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.New(sink.Truncate(err.Error(), 200))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// Elasticsearch reads cluster health (the http_status parser) and the 200 largest indices.
func Elasticsearch(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &TokenConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	hdr := map[string]string{}
	if c.Token != "" {
		hdr["Authorization"] = "ApiKey " + c.Token
	}
	return Loop(ctx, "elasticsearch", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		var h json.RawMessage
		if err := doJSON(ctx, c.HTTPConfig, http.MethodGet, c.URL+"/_cluster/health", hdr, nil, &h); err != nil {
			return err
		}
		if err := EmitElasticsearch(out, h, now); err != nil {
			return err
		}
		var idx []map[string]string
		if err := doJSON(ctx, c.HTTPConfig, http.MethodGet, c.URL+"/_cat/indices?format=json&bytes=b&h=index,health,docs.count,store.size", hdr, nil, &idx); err != nil {
			return err
		}
		EmitElasticsearchIndices(out, idx, now)
		return nil
	})
}

// EmitElasticsearchIndices writes document counts and store sizes of the 200 largest indices.
func EmitElasticsearchIndices(out sink.Sink, idx []map[string]string, now time.Time) {
	size := func(m map[string]string) float64 { f, _ := strconv.ParseFloat(m["store.size"], 64); return f }
	sort.Slice(idx, func(i, j int) bool { return size(idx[i]) > size(idx[j]) })
	for _, m := range idx[:min(len(idx), 200)] {
		a := map[string]string{"elasticsearch.index.name": m["index"]}
		docs, _ := strconv.ParseFloat(m["docs.count"], 64)
		out.Gauge("elasticsearch.index.documents", "{documents}", docs, a, now)
		out.Gauge("elasticsearch.index.store.size", "By", size(m), a, now)
	}
}

// Squid reads the cache manager's counters page (`squid-internal-mgr/counters`).
func Squid(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &HTTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "squid", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		b, err := getBody(ctx, *c, c.URL+"/squid-internal-mgr/counters")
		if err != nil {
			return err
		}
		return EmitSquid(out, b, now)
	})
}

// EmitSquid turns `client_http.requests = 123` lines into cumulative sums (`sample_time` skipped).
func EmitSquid(out sink.Sink, b []byte, now time.Time) error {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		k = strings.TrimSpace(k)
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if !ok || err != nil || k == "" || strings.HasPrefix(k, "sample_time") {
			continue
		}
		out.Sum("squid."+k, "1", f, nil, now)
		n++
	}
	if n == 0 {
		return errors.New("squid: no counters (is cachemgr reachable from this host?)")
	}
	return nil
}

// GitHub reads repository counters and the token's API rate limit.
func GitHub(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &TokenConfig{}
	if len(raw) == 0 || !bytes.Contains(raw, []byte(`"url"`)) {
		raw = mergeURL(raw, "https://api.github.com")
	}
	if err := load(raw, c); err != nil {
		return err
	}
	hdr := map[string]string{"Accept": "application/vnd.github+json"}
	if c.Token != "" {
		hdr["Authorization"] = "Bearer " + c.Token
	}
	return Loop(ctx, "github", c.Base, 5*time.Minute, out, func(ctx context.Context, now time.Time) error {
		var rl struct {
			Resources struct {
				Core struct{ Limit, Remaining float64 } `json:"core"`
			} `json:"resources"`
		}
		if err := doJSON(ctx, c.HTTPConfig, http.MethodGet, c.URL+"/rate_limit", hdr, nil, &rl); err != nil {
			return err
		}
		out.Gauge("github.rate_limit.remaining", "{requests}", rl.Resources.Core.Remaining, nil, now)
		out.Gauge("github.rate_limit.limit", "{requests}", rl.Resources.Core.Limit, nil, now)
		for _, r := range c.Repos {
			var repo map[string]any
			if err := doJSON(ctx, c.HTTPConfig, http.MethodGet, c.URL+"/repos/"+r, hdr, nil, &repo); err != nil {
				return err
			}
			a := map[string]string{"vcs.repository.name": r}
			for k, name := range map[string]string{"stargazers_count": "github.repository.stars", "forks_count": "github.repository.forks",
				"open_issues_count": "github.repository.open_issues", "subscribers_count": "github.repository.watchers", "size": "github.repository.size"} {
				if f, ok := repo[k].(float64); ok {
					out.Gauge(name, "1", f, a, now)
				}
			}
		}
		return nil
	})
}

func mergeURL(raw json.RawMessage, url string) json.RawMessage {
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	m["url"] = url
	b, _ := json.Marshal(m)
	return b
}

// Snowflake runs two ACCOUNT_USAGE queries through the SQL API (programmatic access token):
// credits per warehouse and query counts per status over the last hour.
func Snowflake(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &TokenConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if c.Token == "" {
		return errors.New("snowflake: token (a programmatic access token) is required")
	}
	hdr := map[string]string{"Authorization": "Bearer " + c.Token, "Content-Type": "application/json", "Accept": "application/json",
		"X-Snowflake-Authorization-Token-Type": "PROGRAMMATIC_ACCESS_TOKEN"}
	queries := map[string]string{
		"credits": "SELECT warehouse_name, SUM(credits_used) FROM snowflake.account_usage.warehouse_metering_history WHERE start_time > DATEADD(hour, -1, CURRENT_TIMESTAMP()) GROUP BY 1",
		"queries": "SELECT execution_status, COUNT(*) FROM snowflake.account_usage.query_history WHERE start_time > DATEADD(hour, -1, CURRENT_TIMESTAMP()) GROUP BY 1",
	}
	return Loop(ctx, "snowflake", c.Base, 15*time.Minute, out, func(ctx context.Context, now time.Time) error {
		for kind, q := range queries {
			body, _ := json.Marshal(map[string]any{"statement": q, "timeout": 60, "warehouse": c.Warehouse})
			var res struct {
				Data [][]any `json:"data"`
			}
			if err := doJSON(ctx, c.HTTPConfig, http.MethodPost, c.URL+"/api/v2/statements", hdr, body, &res); err != nil {
				return err
			}
			EmitSnowflake(out, kind, res.Data, now)
		}
		return nil
	})
}

// EmitSnowflake writes one SQL API result (`[[key, number-as-string], ...]`).
func EmitSnowflake(out sink.Sink, kind string, rows [][]any, now time.Time) {
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		f, err := strconv.ParseFloat(fmt.Sprint(r[1]), 64)
		if err != nil {
			continue
		}
		if kind == "credits" {
			out.Gauge("snowflake.warehouse.credits_used", "{credits}", f, map[string]string{"snowflake.warehouse.name": fmt.Sprint(r[0])}, now)
		} else {
			out.Gauge("snowflake.queries", "{queries}", f, map[string]string{"status": fmt.Sprint(r[0])}, now)
		}
	}
}

// Databricks reads cluster states and active job runs of a workspace (personal access token).
func Databricks(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &TokenConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	hdr := map[string]string{"Authorization": "Bearer " + c.Token}
	return Loop(ctx, "databricks", c.Base, time.Minute, out, func(ctx context.Context, now time.Time) error {
		var cl struct {
			Clusters []struct {
				State string `json:"state"`
			} `json:"clusters"`
		}
		if err := doJSON(ctx, c.HTTPConfig, http.MethodGet, c.URL+"/api/2.0/clusters/list", hdr, nil, &cl); err != nil {
			return err
		}
		states := map[string]float64{}
		for _, x := range cl.Clusters {
			states[x.State]++
		}
		for s, n := range states {
			out.Gauge("databricks.clusters", "{clusters}", n, map[string]string{"state": s}, now)
		}
		var runs struct {
			Runs []json.RawMessage `json:"runs"`
		}
		if err := doJSON(ctx, c.HTTPConfig, http.MethodGet, c.URL+"/api/2.1/jobs/runs/list?active_only=true&limit=25", hdr, nil, &runs); err != nil {
			return err
		}
		// shortcut: counts only the first page (25) of active runs; follow next_page_token when needed.
		out.Gauge("databricks.jobs.active_runs", "{runs}", float64(len(runs.Runs)), nil, now)
		return nil
	})
}
