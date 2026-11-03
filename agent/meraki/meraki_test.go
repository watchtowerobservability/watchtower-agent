package meraki

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func find(r *sink.Recorder, name string, kv ...string) (float64, bool) {
next:
	for _, s := range r.Samples {
		if s.Name != name {
			continue
		}
		for i := 0; i+1 < len(kv); i += 2 {
			if s.Attrs[kv[i]] != kv[i+1] {
				continue next
			}
		}
		return s.Value, true
	}
	return 0, false
}

func fixture(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mk-secret" {
			http.Error(w, `{"errors":["Invalid API key"]}`, http.StatusUnauthorized)
			return
		}
		p := r.URL.Path
		switch {
		case p == "/api/v1/organizations":
			fmt.Fprint(w, `[{"id":"o1","name":"Acme"},{"id":"o2","name":"Other"}]`)
		case p == "/api/v1/organizations/o1/networks":
			fmt.Fprint(w, `[{"id":"N1","name":"HQ"}]`)
		case p == "/api/v1/organizations/o1/devices/statuses" && r.URL.Query().Get("startingAfter") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/organizations/o1/devices/statuses?perPage=1000&startingAfter=Q2>; rel=next`, srv.URL))
			fmt.Fprint(w, `[{"name":"mx1","serial":"Q1","networkId":"N1","status":"online","productType":"appliance","model":"MX68"}]`)
		case p == "/api/v1/organizations/o1/devices/statuses":
			fmt.Fprint(w, `[{"name":"","serial":"Q2","networkId":"N1","status":"offline","productType":"wireless","model":"MR36"}]`)
		case p == "/api/v1/organizations/o1/devices/uplinksLossAndLatency":
			fmt.Fprint(w, `[{"networkId":"N1","serial":"Q1","uplink":"wan1","ip":"8.8.8.8",
				"timeSeries":[{"ts":"a","lossPercent":5,"latencyMs":20},{"ts":"b","lossPercent":1.5,"latencyMs":null}]}]`)
		case p == "/api/v1/networks/N1/clients/overview":
			fmt.Fprint(w, `{"counts":{"total":42,"withHeavyUsage":1}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMerakiStatusesUplinksAndClients(t *testing.T) {
	srv := fixture(t)
	c, err := New(Config{BaseURL: srv.URL + "/api/v1", APIKey: "mk-secret"})
	if err != nil {
		t.Fatal(err)
	}
	orgs, err := c.Orgs(context.Background(), []string{"o1"})
	if err != nil || len(orgs) != 1 || orgs[0].Name != "Acme" {
		t.Fatalf("orgs %+v %v", orgs, err)
	}
	rec := &sink.Recorder{}
	if err := c.PollOrg(context.Background(), orgs[0], true, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v, ok := find(rec, "meraki.device.up", "device.id", "Q1", "device.name", "mx1", "meraki.network.name", "HQ"); !ok || v != 1 {
		t.Fatalf("Q1 up %v %v", v, ok)
	}
	if v, ok := find(rec, "meraki.device.status", "device.id", "Q2", "meraki.device.status", "offline"); !ok || v != 1 {
		t.Fatal("second page (Link rel=next) not read")
	}
	if v, ok := find(rec, "meraki.uplink.loss", "device.id", "Q1", "meraki.uplink", "wan1"); !ok || v != 1.5 {
		t.Fatalf("loss %v", v)
	}
	if v, ok := find(rec, "meraki.uplink.latency", "device.id", "Q1"); !ok || v != 20 {
		t.Fatalf("latency keeps the last non-null point, got %v", v)
	}
	if v, ok := find(rec, "meraki.network.clients", "meraki.network.id", "N1"); !ok || v != 42 {
		t.Fatalf("clients %v", v)
	}
	for _, s := range rec.Samples {
		for _, v := range s.Attrs {
			if strings.Contains(v, "mk-secret") {
				t.Fatal("api key in attributes")
			}
		}
	}
}

func TestMerakiRefusesForeignLinksAndPlainHTTP(t *testing.T) {
	c, err := New(Config{BaseURL: "https://api.meraki.com/api/v1", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if c.nextLink(`<https://evil.example/api/v1/x>; rel=next`) != "" {
		t.Fatal("foreign next link followed")
	}
	if c.nextLink(`<http://n1.meraki.com/api/v1/x>; rel=next`) != "" {
		t.Fatal("downgrade to http followed")
	}
	if got := c.nextLink(`<https://n1.meraki.com/api/v1/x?startingAfter=2>; rel="next", <https://api.meraki.com/api/v1/x>; rel=first`); got != "https://n1.meraki.com/api/v1/x?startingAfter=2" {
		t.Fatalf("next %q", got)
	}
	for _, bad := range []Config{{APIKey: "k", BaseURL: "http://api.meraki.com/api/v1"}, {BaseURL: "https://api.meraki.com"}} {
		if _, err := New(bad); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	srv := fixture(t)
	wrong, _ := New(Config{BaseURL: srv.URL + "/api/v1", APIKey: "nope"})
	if _, err := wrong.Orgs(context.Background(), nil); err == nil || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("bad key error %v", err)
	}
}
