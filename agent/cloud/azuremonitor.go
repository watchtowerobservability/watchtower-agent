package cloud

// Azure Monitor pull: the Metrics REST API with a client-credentials OAuth token.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type azureConfig struct {
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Resources     []string `json:"resources"` // full ARM resource ids
	Metrics       []string `json:"metrics"`
	Presets       []string `json:"presets"` // named metric sets added to metrics: azure_functions
	Aggregation   string   `json:"aggregation"` // Average (default), Total, Maximum, Minimum, Count
	LoginEndpoint string   `json:"login_endpoint"`
	Endpoint      string   `json:"endpoint"`
	// Discover lists the subscriptions through Resource Graph (azure_graph.go).
	Discover *azureDiscover `json:"discover"`
}

// azurePresets name a metric set the config can request instead of listing each metric.
var azurePresets = map[string][]string{
	// Azure Functions (D8): execution and error metrics of a Function App.
	"azure_functions": {"FunctionExecutionCount", "FunctionExecutionUnits", "Http5xx"},
}

// azureFaasMetric maps the Function App metrics (lower-cased, spaces -> underscores, as emitted)
// to the OTel faas.* names, so the serverless explorer unifies them with Lambda and Cloud Run.
var azureFaasMetric = map[string]string{
	"functionexecutioncount": "faas.invocations",
	"http5xx":                "faas.errors",
}

type azurePull struct {
	c   azureConfig
	cl  *http.Client
	tok tokenCache
	inv azureInventory
}

func newAzure(raw json.RawMessage) (puller, error) {
	var c azureConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("azure config: malformed")
	}
	c.Metrics = expandPresets(azurePresets, c.Metrics, c.Presets)
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" || (len(c.Resources) == 0 && c.Discover == nil) {
		return nil, errors.New("azure config: tenant_id, client_id, client_secret and resources or discover are required")
	}
	if c.Discover != nil {
		if err := c.Discover.check(); err != nil {
			return nil, err
		}
	}
	if len(c.Metrics) == 0 && (len(c.Resources) > 0 || (c.Discover != nil && len(c.Discover.ResourceTypes) > 0)) {
		return nil, errors.New("azure config: metrics are required to poll resources")
	}
	for _, r := range c.Resources {
		// Joined to the endpoint: "@evil.example/x" would change the host the token goes to.
		if !strings.HasPrefix(r, "/") {
			return nil, errors.New("azure config: resources must be ARM ids starting with /")
		}
	}
	if c.Aggregation == "" {
		c.Aggregation = "Average"
	}
	if c.LoginEndpoint == "" {
		c.LoginEndpoint = "https://login.microsoftonline.com"
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://management.azure.com"
	}
	return &azurePull{c: c, cl: httpClient()}, nil
}

func (a *azurePull) token(ctx context.Context, now time.Time) (string, error) {
	return a.tok.get(now, func() (string, time.Duration, error) {
		return tokenForm(ctx, a.cl, a.c.LoginEndpoint+"/"+url.PathEscape(a.c.TenantID)+"/oauth2/v2.0/token", url.Values{
			"grant_type": {"client_credentials"}, "client_id": {a.c.ClientID},
			"client_secret": {a.c.ClientSecret}, "scope": {"https://management.azure.com/.default"},
		})
	})
}

type azureMetrics struct {
	Value []struct {
		Name       struct{ Value string } `json:"name"`
		Unit       string                 `json:"unit"`
		Timeseries []struct {
			Data []map[string]any `json:"data"`
		} `json:"timeseries"`
	} `json:"value"`
}

// azureNamespace turns ".../providers/Microsoft.Compute/virtualMachines/vm1" into
// "microsoft.compute.virtualmachines" and returns the resource name.
func azureNamespace(id string) (ns, name string) {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i, p := range parts {
		if strings.EqualFold(p, "providers") && i+3 < len(parts) {
			return strings.ToLower(parts[i+1] + "." + parts[i+2]), parts[len(parts)-1]
		}
	}
	return "unknown", parts[len(parts)-1]
}

func (a *azurePull) pull(ctx context.Context, from, to time.Time, e *emitter) error {
	tok, err := a.token(ctx, to)
	if err != nil {
		return err
	}
	field := strings.ToLower(a.c.Aggregation) // data keys are average, total, maximum, minimum, count
	ids := a.c.Resources
	if a.c.Discover != nil {
		found, err := a.discovered(ctx, tok, to, e.out)
		if err != nil {
			// Reported, not returned: the metric window must keep moving for the known resources.
			e.out.Log("WARN", "azure resource graph: "+err.Error(), map[string]string{"cloud.provider": "azure"}, to)
		}
		ids = pollIDs(a.c.Resources, found)
	}
	explicit := len(a.c.Resources)
	for i, res := range ids {
		q := url.Values{
			"api-version": {"2018-01-01"}, "metricnames": {strings.Join(a.c.Metrics, ",")},
			"timespan": {from.UTC().Format(time.RFC3339) + "/" + to.UTC().Format(time.RFC3339)},
			"interval": {"PT1M"}, "aggregation": {a.c.Aggregation},
		}
		var r azureMetrics
		u := a.c.Endpoint + res + "/providers/microsoft.insights/metrics?" + q.Encode()
		if err := doJSON(ctx, a.cl, "GET", u, map[string]string{"Authorization": "Bearer " + tok}, nil, &r); err != nil {
			var rl *rateLimitErr
			if i < explicit || errors.As(err, &rl) {
				return err
			}
			continue // a discovered resource that lacks one of the metrics must not stop the rest
		}
		ns, name := azureNamespace(res)
		sub := ""
		if parts := strings.Split(strings.Trim(res, "/"), "/"); len(parts) > 1 && strings.EqualFold(parts[0], "subscriptions") {
			sub = parts[1]
		}
		resAttrs := map[string]string{"cloud.account.id": sub, "cloud.resource_id": name}
		for _, m := range r.Value {
			metric := strings.ToLower(strings.ReplaceAll(m.Name.Value, " ", "_"))
			for _, ts := range m.Timeseries {
				for _, d := range ts.Data {
					at, _ := time.Parse(time.RFC3339, str(d["timeStamp"]))
					v, ok := d[field].(float64)
					if !ok || at.IsZero() {
						continue
					}
					e.gauge("cloud.azure."+ns+"."+metric, m.Unit, v, at, resAttrs, nil)
					if fm, ok := azureFaasMetric[metric]; ok {
						e.gauge(fm, m.Unit, v, at, map[string]string{
							"cloud.account.id": sub, "cloud.resource_id": name,
							"faas.name": name, "cloud.platform": "azure_functions",
						}, nil)
					}
				}
			}
		}
	}
	return nil
}

func str(v any) string { s, _ := v.(string); return s }
