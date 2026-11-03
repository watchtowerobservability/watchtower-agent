package hw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestPowerStoreSpaceVolumesHardware(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "mon" || p != "ps-secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/rest/login_session":
			http.SetCookie(w, &http.Cookie{Name: "auth_cookie", Value: "c1", Path: "/"})
			w.Header().Set("DELL-EMC-TOKEN", "csrf1")
			_, _ = w.Write([]byte(`[{"id":"s1"}]`))
		case "/api/rest/appliance":
			_, _ = w.Write([]byte(`[{"id":"A1","name":"ps-appl"}]`))
		case "/api/rest/metrics/generate":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			ck, _ := r.Cookie("auth_cookie")
			if r.Method != http.MethodPost || r.Header.Get("DELL-EMC-TOKEN") != "csrf1" || ck == nil || body["entity_id"] != "A1" {
				http.Error(w, "csrf", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`[{"physical_total":9000,"physical_used":1000},{"physical_total":10000,"physical_used":2500,"data_reduction":4.2}]`))
		case "/api/rest/volume":
			_, _ = w.Write([]byte(`[{"id":"v1","name":"db","size":500,"state":"Ready"},{"id":"v2","name":"old","size":5,"state":"Offline"}]`))
		case "/api/rest/hardware":
			_, _ = w.Write([]byte(`[{"id":"d1","name":"Drive_0_0","type":"Drive","lifecycle_state":"Faulted","serial_number":"S1"},
				{"id":"p1","name":"PSU_A","type":"Power_Supply","lifecycle_state":"Healthy"},{"id":"d9","type":"Drive","lifecycle_state":"Empty"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "ps1", Vendor: "powerstore", BaseURL: srv.URL, Username: "mon", PasswordFile: secretFile(t, "ps-secret"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "hw.array.up", "hw.array", "ps1", "hw.vendor", "powerstore")
	want(t, rec, 10000, "hw.logical_disk.limit", "hw.id", "A1")
	want(t, rec, 2500, "hw.logical_disk.usage", "hw.id", "A1")
	want(t, rec, 4.2, "hw.array.data_reduction", "hw.id", "A1")
	want(t, rec, 500, "hw.logical_disk.limit", "hw.id", "v1")
	want(t, rec, 1, "hw.status", "hw.id", "v2", "hw.state", "failed")
	want(t, rec, 1, "hw.status", "hw.id", "d1", "hw.type", "physical_disk", "hw.state", "failed")
	want(t, rec, 1, "hw.status", "hw.id", "p1", "hw.type", "power_supply", "hw.state", "ok")
	if _, ok := find(rec, "hw.status", "hw.id", "d9"); ok {
		t.Fatal("empty slot reported")
	}
}

func TestHPEWSAPISessionCapacityAndLogout(t *testing.T) {
	loggedOut := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/credentials" {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Method != http.MethodPost || b["user"] != "mon" || b["password"] != "hpe-secret" {
				http.Error(w, "no", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"key":"k/1"}`))
			return
		}
		if r.Header.Get("X-HP3PAR-WSAPI-SessionKey") != "k/1" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodDelete && r.URL.EscapedPath() == "/api/v1/credentials/k%2F1":
			loggedOut = true
		case r.URL.Path == "/api/v1/system":
			_, _ = w.Write([]byte(`{"name":"3par1","totalCapacityMiB":1024,"allocatedCapacityMiB":512,"freeCapacityMiB":512,"clusterNodes":[0,1],"onlineNodes":[0]}`))
		case r.URL.Path == "/api/v1/cpgs":
			_, _ = w.Write([]byte(`{"total":1,"members":[{"name":"FC_r6","state":2,"UsrUsage":{"totalMiB":100,"usedMiB":40},"SDUsage":{"totalMiB":20,"usedMiB":10}}]}`))
		case r.URL.Path == "/api/v1/volumes":
			_, _ = w.Write([]byte(`{"total":2,"members":[{"name":"vv1","state":1,"sizeMiB":10,"totalUsedMiB":4},{"name":"vv2","state":1,"sizeMiB":2,"userSpace":{"usedMiB":1}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "hpe1", Vendor: "hpe", BaseURL: srv.URL, Username: "mon", PasswordFile: secretFile(t, "hpe-secret"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !loggedOut {
		t.Fatal("session not closed")
	}
	want(t, rec, 1024*mibBytes, "hw.logical_disk.limit", "hw.id", "3par1")
	want(t, rec, 512*mibBytes, "hw.logical_disk.usage", "hw.id", "3par1")
	want(t, rec, 1, "hw.status", "hw.id", "node1", "hw.type", "disk_controller", "hw.state", "failed")
	want(t, rec, 1, "hw.status", "hw.id", "node0", "hw.state", "ok")
	want(t, rec, 120*mibBytes, "hw.logical_disk.limit", "hw.id", "FC_r6")
	want(t, rec, 50*mibBytes, "hw.logical_disk.usage", "hw.id", "FC_r6")
	want(t, rec, 1, "hw.status", "hw.id", "FC_r6", "hw.state", "degraded")
	want(t, rec, 4*mibBytes, "hw.logical_disk.usage", "hw.id", "vv1")
	want(t, rec, 1*mibBytes, "hw.logical_disk.usage", "hw.id", "vv2")
	for _, s := range rec.Samples {
		for _, v := range s.Attrs {
			if strings.Contains(v, "hpe-secret") || strings.Contains(v, "k/1") {
				t.Fatalf("leak: %v", s.Attrs)
			}
		}
	}
}

func TestNewVendorsNeedUsernameAndPinOrigin(t *testing.T) {
	for _, v := range []string{"powerstore", "hpe"} {
		if _, err := newArrayClient(Array{Vendor: v, BaseURL: "https://x"}); err == nil {
			t.Fatalf("%s without username accepted", v)
		}
	}
	c := &arrayClient{origin: &url.URL{Scheme: "https", Host: "ps.local"}}
	if _, err := c.at("https://evil.example/api/rest/volume"); err == nil {
		t.Fatal("foreign origin accepted")
	}
}
