package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSelectorMatchers(t *testing.T) {
	got, err := SelectorMatchers("topic=orders,group in (b,a),env!=dev,team")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`topic="orders"`, `group=~"a|b"`, `env!="dev"`, `team!=""`} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %s", got, want)
		}
	}
	if _, err := SelectorMatchers(`a/b=c`); err == nil {
		t.Error("a prefixed label key is not a metric label")
	}
}

func TestExternalMetricsServesHPAQueries(t *testing.T) {
	var gotQ string
	e := &ExtMetrics{Metrics: map[string]string{"queue_lag": "sum(lag{ {{selector}} })"}, Now: func() time.Time { return time.Unix(0, 0) },
		Query: func(_ context.Context, q string) ([]ExtSample, error) {
			gotQ = q
			return []ExtSample{{Labels: map[string]string{"topic": "orders"}, Value: 1.5}}, nil
		}}
	srv := httptest.NewServer(e)
	defer srv.Close()
	resp, err := http.Get(srv.URL + extGroup + "/namespaces/shop/queue_lag?labelSelector=topic%3Dorders")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			MetricName string `json:"metricName"`
			Value      string `json:"value"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotQ != `sum(lag{ topic="orders" })` || list.Kind != "ExternalMetricValueList" || len(list.Items) != 1 || list.Items[0].Value != "1500m" {
		t.Fatalf("query %q list %+v", gotQ, list)
	}
	r2, _ := http.Get(srv.URL + extGroup + "/namespaces/shop/unknown")
	r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown metric: %d", r2.StatusCode)
	}
	r3, _ := http.Get(srv.URL + extGroup)
	var rl struct {
		Resources []struct {
			Name string `json:"name"`
		} `json:"resources"`
	}
	_ = json.NewDecoder(r3.Body).Decode(&rl)
	r3.Body.Close()
	if len(rl.Resources) != 1 || rl.Resources[0].Name != "queue_lag" {
		t.Fatalf("discovery %+v", rl)
	}
}
