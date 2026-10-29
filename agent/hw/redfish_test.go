package hw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const thermalWarningDocs = `{
 "/redfish/v1": {"Systems": {"@odata.id": "/redfish/v1/Systems"}, "Chassis": {"@odata.id": "/redfish/v1/Chassis"}},
 "/redfish/v1/Systems": {"Members": []},
 "/redfish/v1/Chassis": {"Members": [{"@odata.id": "/redfish/v1/Chassis/1"}]},
 "/redfish/v1/Chassis/1": {"Id": "1", "Name": "Rack", "Status": {"State": "Enabled", "Health": "OK"}, "Thermal": {"@odata.id": "/redfish/v1/Chassis/1/Thermal"}},
 "/redfish/v1/Chassis/1/Thermal": {"Temperatures": [{"MemberId": "0", "Name": "Inlet", "ReadingCelsius": 41, "Status": {"State": "Enabled", "Health": "Warning"}}]}
}`

// TestThermalWarningMapsToEntities checks that a thermal warning carries the host, service, SLO,
// on-call team and workloads configured for the BMC, so alerts and incidents can be scoped by them.
func TestThermalWarningMapsToEntities(t *testing.T) {
	docs := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(thermalWarningDocs), &docs); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(d)
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	r := Redfish{Name: "bmc1", BaseURL: srv.URL, Scope: Scope{
		Host: "db-1", Service: "checkout", SLO: "checkout-availability", OnCall: "payments", Workloads: []string{"checkout-db", "ledger"},
	}}
	if err := PollRedfish(context.Background(), r, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "hw.status", "hw.type", "temperature", "hw.state", "degraded",
		"hw.host", "db-1", "hw.service", "checkout", "hw.slo", "checkout-availability",
		"hw.oncall_team", "payments", "hw.workloads", "checkout-db,ledger")
	want(t, rec, 41, "hw.temperature", "hw.host", "db-1")
}

func TestEmptyScopeAddsNothing(t *testing.T) {
	rec := &sink.Recorder{}
	withScope(rec, Scope{}).Gauge("x", "1", 1, map[string]string{"a": "b"}, time.Now())
	if s, _ := find(rec, "x"); len(s.Attrs) != 1 {
		t.Fatalf("attrs %v", s.Attrs)
	}
}
