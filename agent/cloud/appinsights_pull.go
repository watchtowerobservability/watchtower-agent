package cloud

// Hosted Application Insights traces (TRC-007), provider "azure_appinsights": instead of the Event
// Hubs export (eventhub.go), the pull queries the Log Analytics workspace behind a workspace-based
// App Insights resource for AppRequests and AppDependencies rows and maps them with the same
// appInsightsSpan. The cursor is the rows' ingestion time, not their TimeGenerated, so a row that
// arrives minutes late is still read; a one-minute overlap is deduplicated by row id
// (at-least-once, no double spans within a process). Every call goes through tenantClient. A sink
// that is a cursorStore (hosted and data-plane pulls: Postgres cloud_pull_cursors) keeps the
// position per pull and workspace, saved only after the spans were flushed, so a restart resumes.
// A BYOC agent keeps it in its state dir instead (cursor_file.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	aiRowsPerQuery = 5000
	aiOverlap      = time.Minute
	aiMaxWorkspace = 20
)

type appInsightsConfig struct {
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Workspaces    []string `json:"workspaces"` // Log Analytics workspace ids (GUIDs)
	LoginEndpoint string   `json:"login_endpoint"`
	Endpoint      string   `json:"endpoint"`
	PullID        string   `json:"pull_id"` // set by internal/cloudpull from the row, never by the tenant
}

// cursorStore is a sink that keeps pull positions across restarts.
type cursorStore interface {
	LoadCursor(ctx context.Context, pull, key string) (time.Time, bool)
	SaveCursor(ctx context.Context, pull, key string, at time.Time) error
	Flush(ctx context.Context) error
}

type appInsightsPull struct {
	c     appInsightsConfig
	cl    *http.Client
	tok   tokenCache
	store cursorStore                     // nil: the position lives only in memory (no state dir)
	since map[string]time.Time            // per workspace: newest ingestion time read
	seen  map[string]map[string]time.Time // per workspace: row id -> ingestion time, inside the overlap
}

func newAppInsights(raw json.RawMessage) (*appInsightsPull, error) {
	var c appInsightsConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("azure_appinsights config: malformed")
	}
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" || len(c.Workspaces) == 0 || len(c.Workspaces) > aiMaxWorkspace {
		return nil, errors.New("azure_appinsights config: tenant_id, client_id, client_secret and 1 to 20 workspaces are required")
	}
	for _, w := range c.Workspaces {
		// joined to the endpoint path: "../" or "@host" must not change where the token goes
		if w == "" || strings.ContainsAny(w, "/@?#%.") {
			return nil, errors.New("azure_appinsights config: workspaces must be workspace ids")
		}
	}
	if c.LoginEndpoint == "" {
		c.LoginEndpoint = "https://login.microsoftonline.com"
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://api.loganalytics.io"
	}
	return &appInsightsPull{c: c, cl: httpClient(), since: map[string]time.Time{}, seen: map[string]map[string]time.Time{}}, nil
}

func (a *appInsightsPull) token(ctx context.Context, now time.Time) (string, error) {
	return a.tok.get(now, func() (string, time.Duration, error) {
		return tokenForm(ctx, a.cl, a.c.LoginEndpoint+"/"+url.PathEscape(a.c.TenantID)+"/oauth2/v2.0/token", url.Values{
			"grant_type": {"client_credentials"}, "client_id": {a.c.ClientID},
			"client_secret": {a.c.ClientSecret}, "scope": {"https://api.loganalytics.io/.default"},
		})
	})
}

// aiQuery is the KQL of one run; `from` is formatted by the caller, never tenant text.
func aiQuery(from time.Time) string {
	return "union AppRequests, AppDependencies | extend _wt_ingested = ingestion_time() " +
		"| where _wt_ingested > datetime(" + from.UTC().Format(time.RFC3339Nano) + ") " +
		"| order by _wt_ingested asc | take " + fmt.Sprint(aiRowsPerQuery)
}

type aiTable struct {
	Columns []struct {
		Name string `json:"name"`
	} `json:"columns"`
	Rows [][]any `json:"rows"`
}

// aiRow turns one result row into the record shape appInsightsSpan reads. Properties is a
// dynamic column, which the query API returns as JSON text.
func aiRow(cols []string, row []any) (json.RawMessage, string, time.Time) {
	m := map[string]any{}
	for i, c := range cols {
		if i < len(row) && row[i] != nil {
			m[c] = row[i]
		}
	}
	if s, ok := m["Properties"].(string); ok {
		var props map[string]any
		if json.Unmarshal([]byte(s), &props) == nil {
			flat := map[string]string{}
			for k, v := range props {
				if vs, ok := v.(string); ok {
					flat[k] = vs
				} else if b, err := json.Marshal(v); err == nil {
					flat[k] = string(b)
				}
			}
			m["Properties"] = flat
		} else {
			delete(m, "Properties")
		}
	}
	at, _ := time.Parse(time.RFC3339Nano, str(m["_wt_ingested"]))
	raw, _ := json.Marshal(m)
	return raw, str(m["Type"]) + "/" + str(m["Id"]), at
}

// pullWorkspace reads the rows ingested since the cursor and ships their spans.
func (a *appInsightsPull) pullWorkspace(ctx context.Context, ws string, now time.Time, ship func(map[string]string, []*tracepb.Span)) error {
	tok, err := a.token(ctx, now)
	if err != nil {
		return err
	}
	since, ok := a.since[ws]
	if !ok && a.store != nil && a.c.PullID != "" {
		since, ok = a.store.LoadCursor(ctx, a.c.PullID, ws)
	}
	if !ok {
		since = now.Add(-aiOverlap) // a new pull starts now; it does not backfill the workspace
	}
	// the timespan (ISO 8601) bounds the scan to a day of TimeGenerated
	body, _ := json.Marshal(map[string]string{"query": aiQuery(since.Add(-aiOverlap)), "timespan": "P1D"})
	var out struct {
		Tables []aiTable `json:"tables"`
	}
	err = doJSON(ctx, a.cl, http.MethodPost, a.c.Endpoint+"/v1/workspaces/"+url.PathEscape(ws)+"/query",
		map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, bytes.NewReader(body), &out)
	if err != nil {
		return fmt.Errorf("workspace %s: %w", ws, err)
	}
	seen := a.seen[ws]
	if seen == nil {
		seen = map[string]time.Time{}
		a.seen[ws] = seen
	}
	newest := since
	for _, t := range out.Tables {
		cols := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			cols[i] = c.Name
		}
		for _, row := range t.Rows {
			raw, id, at := aiRow(cols, row)
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = at
			if at.After(newest) {
				newest = at
			}
			if res, sp, ok := appInsightsSpan(raw); ok {
				ship(res, []*tracepb.Span{sp})
			}
		}
	}
	a.since[ws] = newest
	if a.store != nil && a.c.PullID != "" {
		// persist only what reached the gateway; a refused flush is retried from the sink's buffer
		if err := a.store.Flush(ctx); err != nil {
			return fmt.Errorf("workspace %s: %w", ws, err)
		}
		if err := a.store.SaveCursor(ctx, a.c.PullID, ws, newest); err != nil {
			return fmt.Errorf("workspace %s: save position: %w", ws, err)
		}
	}
	for id, at := range seen {
		if at.Before(newest.Add(-2 * aiOverlap)) {
			delete(seen, id)
		}
	}
	return nil
}

// run pulls every workspace each interval until ctx ends; errors go to out.Log without secrets.
func (a *appInsightsPull) run(ctx context.Context, every time.Duration, ship func(map[string]string, []*tracepb.Span), out sink.Sink) {
	for {
		for _, ws := range a.c.Workspaces {
			if err := a.pullWorkspace(ctx, ws, time.Now(), ship); err != nil && ctx.Err() == nil {
				out.Log("ERROR", "azure_appinsights pull: "+err.Error(), map[string]string{"cloud.provider": "azure"}, time.Now())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// spanShipper is the sink's span intake, nil for a sink that only takes datapoints.
func spanShipper(out sink.Sink) func(map[string]string, []*tracepb.Span) {
	if sa, ok := out.(interface {
		AddSpans(map[string]string, []*tracepb.Span)
	}); ok {
		return sa.AddSpans
	}
	return nil
}
