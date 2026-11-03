package cloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// The bodies below are cut from the examples in each provider's public API reference (Azure Monitor
// Metrics - List, CloudWatch GetMetricData, Cloud Monitoring TimeSeries, Cloudflare GraphQL, Vercel
// list deployments); the Cloudflare zone dataset's fields come from the existing query, not a doc example. No test
// here, and no other check, has run against a real account.

var (
	liveFrom = time.Date(2021, 4, 20, 9, 0, 0, 0, time.UTC)
	liveTo   = liveFrom.Add(time.Hour)
)

func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s.URL
}

func TestLiveAzureDocsShape(t *testing.T) {
	var asked url.Values
	base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		asked = r.URL.Query()
		fmt.Fprint(w, `{"cost":598,"timespan":"2021-04-20T09:00:00Z/2021-04-20T14:00:00Z","interval":"PT1H","value":[
		{"id":"/x/metrics/BlobCount","type":"Microsoft.Insights/metrics","name":{"value":"BlobCount","localizedValue":"Blob Count"},
		"unit":"Count","timeseries":[{"metadatavalues":[{"name":{"value":"tier","localizedValue":"tier"},"value":"Hot"}],
		"data":[{"timeStamp":"2021-04-20T09:00:00Z","average":7,"minimum":7,"maximum":7},
		{"timeStamp":"2021-04-20T10:00:00Z","average":8,"minimum":7,"maximum":7}]}],"errorCode":"Success"}],
		"namespace":"microsoft.storage/storageaccounts/blobservices","resourceregion":"westus2"}`)
	})
	res := "/subscriptions/s1/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/a"
	cfg := map[string]any{"tenant_id": "t", "client_id": "c", "client_secret": "s", "endpoint": base, "login_endpoint": base,
		"resources": []any{res}, "metrics": []any{"BlobCount", "BlobCapacity"}}
	got, err := Query(context.Background(), "azure", cfg, LiveQuery{Metrics: []string{"BlobCount"}}, liveFrom, liveTo)
	if err != nil {
		t.Fatal(err)
	}
	if asked.Get("metricnames") != "BlobCount" {
		t.Fatalf("metricnames = %q", asked.Get("metricnames"))
	}
	if len(got) != 1 || len(got[0].Points) != 2 || got[0].Points[1].V != 8 || !strings.HasSuffix(got[0].Name, ".blobcount") {
		t.Fatalf("%+v", got)
	}
}

func TestLiveCloudWatchDocsShape(t *testing.T) {
	base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		w.Header().Set("Content-Type", "text/xml")
		if form.Get("Action") == "ListMetrics" {
			fmt.Fprint(w, `<ListMetricsResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/"><ListMetricsResult><Metrics>
			<member><Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName><Dimensions><member><Name>InstanceId</Name><Value>i-1234567890abcdef0</Value></member></Dimensions></member>
			<member><Namespace>AWS/EC2</Namespace><MetricName>NetworkOut</MetricName></member>
			</Metrics></ListMetricsResult></ListMetricsResponse>`)
			return
		}
		fmt.Fprint(w, `<GetMetricDataResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/"><GetMetricDataResult><MetricDataResults>
		<member><Id>q0</Id><Label>CPUUtilization</Label><StatusCode>Complete</StatusCode>
		<Timestamps><member>2018-02-17T11:47:12Z</member><member>2018-02-17T11:42:12Z</member><member>2018-02-17T11:37:12Z</member></Timestamps>
		<Values><member>15</member><member>14</member><member>16</member></Values></member>
		</MetricDataResults></GetMetricDataResult></GetMetricDataResponse>`)
	})
	cfg := map[string]any{"access_key_id": "AKIDEXAMPLE", "secret_access_key": "x", "region": "eu-west-1", "endpoint": base, "namespaces": []any{"AWS/EC2"}}
	got, err := Query(context.Background(), "aws", cfg, LiveQuery{Metric: "CPUUtilization"}, liveFrom, liveTo)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Points) != 3 || got[0].Points[0].V != 16 || got[0].Attrs["aws.dim.InstanceId"] != "i-1234567890abcdef0" {
		t.Fatalf("every point, oldest first: %+v", got)
	}
}

func TestLiveCloudflareDocsShape(t *testing.T) {
	base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `{"data":{"viewer":{"zones":[{"httpRequests1mGroups":[{"dimensions":{"datetimeMinute":"2021-04-20T09:00:00Z"},
		"sum":{"requests":10,"cachedRequests":4,"bytes":100,"threats":0}}]}]}},"errors":null}`)
	})
	cfg := map[string]any{"api_token": "cf", "endpoint": base, "zone_ids": []any{"z1", "z2"}}
	got, err := Query(context.Background(), "cloudflare", cfg, LiveQuery{ZoneIDs: []string{"z1"}}, liveFrom, liveTo)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("one series per sum field: %+v", got)
	}
}

func TestLiveVercelDocsShape(t *testing.T) {
	var asked url.Values
	base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Query()
		if r.URL.Path != "/v7/deployments" || r.Header.Get("Authorization") != "Bearer vc" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, `{"deployments":[{"name":"docs","projectId":"example_id","readyState":"READY","state":"READY","target":"production",
		"created":"1609492210000","buildingAt":"1609492210000","ready":1609492270000,"uid":"dpl_1","url":"docs.vercel.app"}],
		"pagination":{"count":"20","next":"1540095775951","prev":"1540095775951"}}`)
	})
	got, err := Query(context.Background(), "vercel", map[string]any{"api_token": "vc", "endpoint": base, "team_id": "tm"}, LiveQuery{}, liveFrom, liveTo)
	if err != nil {
		t.Fatal(err)
	}
	if asked.Get("teamId") != "tm" || asked.Get("since") != fmt.Sprint(liveFrom.UnixMilli()) {
		t.Fatalf("%v", asked)
	}
	if len(got) != 2 || got[0].Name != "cloud.vercel.deployment.build_time" || got[0].Points[0].V != 60 {
		t.Fatalf("%+v", got)
	}
}

func TestLiveQueryCannotWidenTheRow(t *testing.T) {
	cfg := map[string]any{"metrics": []any{"a"}}
	_, err := Query(context.Background(), "gcp", cfg, LiveQuery{Metrics: []string{"b"}}, liveFrom, liveTo)
	if !errors.Is(err, ErrBadLiveQuery) {
		t.Fatalf("%v", err)
	}
	_, err = Query(context.Background(), "gcp", cfg, LiveQuery{}, liveTo, liveFrom)
	if !errors.Is(err, ErrBadLiveQuery) {
		t.Fatalf("%v", err)
	}
}

func TestLiveInertWithoutCredentials(t *testing.T) {
	for _, p := range []string{"aws", "gcp", "azure", "cloudflare", "vercel"} {
		_, err := Query(context.Background(), p, map[string]any{}, LiveQuery{}, liveFrom, liveTo)
		if !errors.Is(err, ErrBadLiveQuery) {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

func TestMain(m *testing.M) {
	tenantClient = httpClient // tests reach local servers; TestTenantClientRefusesPrivate checks the real one
	os.Exit(m.Run())
}

func TestStoredEndpointCannotRedirectCredential(t *testing.T) {
	var got string
	evil := serve(t, func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") })
	cfg := map[string]any{"endpoint": evil, "login_endpoint": evil}
	MergeCredential(cfg, map[string]any{"api_token": "vc"})
	if _, ok := cfg["endpoint"]; ok {
		t.Fatalf("a row's endpoint survived: %v", cfg)
	}
	if _, ok := cfg["login_endpoint"]; ok {
		t.Fatalf("a row's login endpoint survived: %v", cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the default host is never dialled
	_, _ = Query(ctx, "vercel", cfg, LiveQuery{}, liveFrom, liveTo)
	if got != "" {
		t.Fatal("credential sent to the stored endpoint")
	}
	sealed := map[string]any{"endpoint": evil}
	MergeCredential(sealed, map[string]any{"endpoint": "https://sealed.example"})
	if sealed["endpoint"] != "https://sealed.example" {
		t.Fatalf("the endpoint sealed with the credential counts: %v", sealed)
	}
}

func TestTenantClientRefusesPrivate(t *testing.T) {
	base := serve(t, func(http.ResponseWriter, *http.Request) {})
	if resp, err := strictTenantClient().Get(base); err == nil {
		resp.Body.Close()
		t.Fatal("reached a loopback address")
	}
}

func TestAzureResourceCannotChangeHost(t *testing.T) {
	_, err := newAzure([]byte(`{"tenant_id":"t","client_id":"c","client_secret":"s","metrics":["m"],"resources":["@evil.example/x"]}`))
	if err == nil {
		t.Fatal("accepted a resource that rewrites the host")
	}
}

func TestLiveGCPDocsShape(t *testing.T) {
	_, pemKey := testKeyPEM(t)
	base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		fmt.Fprint(w, `{"timeSeries":[{"metric":{"type":"compute.googleapis.com/instance/uptime","labels":{}},
		"resource":{"type":"gce_instance","labels":{"instance_id":"123"}},"metricKind":"DELTA","valueType":"INT64",
		"points":[{"interval":{"startTime":"2021-04-20T09:00:00Z","endTime":"2021-04-20T09:01:00Z"},"value":{"int64Value":"60"}},
		{"interval":{"startTime":"2021-04-20T09:01:00Z","endTime":"2021-04-20T09:02:00Z"},"value":{"doubleValue":59.5}}]}]}`)
	})
	cfg := map[string]any{"project": "p", "metrics": []any{"compute.googleapis.com/instance/uptime"}, "endpoint": base,
		"service_account": map[string]any{"client_email": "sa@p.iam", "private_key": pemKey, "token_uri": base + "/token"}}
	got, err := Query(context.Background(), "gcp", cfg, LiveQuery{}, liveFrom, liveTo)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Points) != 2 || got[0].Points[0].V != 60 || got[0].Points[1].V != 59.5 {
		t.Fatalf("%+v", got)
	}
}

func TestLiveVercelFollowsPagesAndAWSStatIsChecked(t *testing.T) {
	var untils []string
	mid := liveFrom.Add(30 * time.Minute).UnixMilli()
	base := serve(t, func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("until")
		untils = append(untils, u)
		next := fmt.Sprint(mid)
		if u == next {
			next = "null"
		}
		fmt.Fprintf(w, `{"deployments":[{"name":"d","projectId":"p","readyState":"READY","target":"production","created":%d}],"pagination":{"next":%s}}`, mid, next)
	})
	if _, err := Query(context.Background(), "vercel", map[string]any{"api_token": "vc", "endpoint": base}, LiveQuery{}, liveFrom, liveTo); err != nil {
		t.Fatal(err)
	}
	if len(untils) != 2 || untils[1] != fmt.Sprint(mid) {
		t.Fatalf("pages asked: %v", untils)
	}
	cfg := map[string]any{"access_key_id": "a", "secret_access_key": "x", "region": "eu-west-1", "namespaces": []any{"AWS/EC2"}}
	if _, err := Query(context.Background(), "aws", cfg, LiveQuery{Stat: "p99; drop"}, liveFrom, liveTo); !errors.Is(err, ErrBadLiveQuery) {
		t.Fatalf("bad stat: %v", err)
	}
}
