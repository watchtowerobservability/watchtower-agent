package hw

import (
	"bufio"
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func find(r *sink.Recorder, name string, kv ...string) (sink.Sample, bool) {
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
		return s, true
	}
	return sink.Sample{}, false
}

func want(t *testing.T, r *sink.Recorder, v float64, name string, kv ...string) {
	t.Helper()
	s, ok := find(r, name, kv...)
	if !ok {
		t.Fatalf("no %s with %v in %+v", name, kv, r.Samples)
	}
	if math.Abs(s.Value-v) > 1e-6 {
		t.Fatalf("%s = %v, want %v", name, s.Value, v)
	}
}

func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	b, err := os.ReadFile("testdata/redfish.json")
	if err != nil {
		t.Fatal(err)
	}
	var docs map[string]json.RawMessage
	if err := json.Unmarshal(b, &docs); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "monitor" || p != "bmc-secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		d, ok := docs[strings.TrimRight(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(d)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRedfishThermalFromFixtureServer(t *testing.T) {
	srv := fixtureServer(t)
	rec := &sink.Recorder{}
	err := PollRedfish(context.Background(), Redfish{Name: "bmc1", BaseURL: srv.URL, Username: "monitor", Password: "bmc-secret"}, rec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "hw.bmc.up", "hw.bmc", "bmc1")
	want(t, rec, 54, "hw.temperature", "hw.name", "CPU1 Temp", "hw.chassis", "1")
	want(t, rec, 5400, "hw.fan.speed", "hw.name", "Fan1")
	want(t, rec, 0.4, "hw.fan.speed_ratio", "hw.name", "Fan2")
	want(t, rec, 312, "hw.power", "hw.power.direction", "input")
	want(t, rec, 150, "hw.power", "hw.power.direction", "output")
	want(t, rec, 12.1, "hw.voltage", "hw.name", "12V")
	want(t, rec, 1, "hw.status", "hw.type", "enclosure", "hw.state", "ok")
	want(t, rec, 1, "hw.status", "hw.type", "power_supply", "hw.state", "ok")
	for _, s := range rec.Samples {
		for _, v := range s.Attrs {
			if strings.Contains(v, srv.URL) || v == "bmc-secret" {
				t.Fatalf("address or password leaked: %v", s.Attrs)
			}
		}
	}
}

func TestRedfishStorageDrives(t *testing.T) {
	srv := fixtureServer(t)
	rec := &sink.Recorder{}
	if err := PollRedfish(context.Background(), Redfish{Name: "bmc1", BaseURL: srv.URL, Username: "monitor", Password: "bmc-secret"}, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 4e12, "hw.physical_disk.size", "hw.id", "D0")
	want(t, rec, 1, "hw.status", "hw.type", "physical_disk", "hw.id", "D0", "hw.state", "ok")
	want(t, rec, 1, "hw.status", "hw.type", "physical_disk", "hw.id", "D1", "hw.state", "failed")
	want(t, rec, 8e12, "hw.logical_disk.limit", "hw.id", "V0")
	want(t, rec, 1, "hw.status", "hw.type", "logical_disk", "hw.state", "degraded")
	want(t, rec, 1, "hw.status", "hw.type", "disk_controller", "hw.state", "ok")
}

func TestHWStatusHasOneSeriesPerState(t *testing.T) {
	rec := &sink.Recorder{}
	emitState(rec, map[string]string{"hw.id": "D1"}, "physical_disk", "failed", time.Now())
	want(t, rec, 0, "hw.status", "hw.state", "ok")
	want(t, rec, 0, "hw.status", "hw.state", "degraded")
	want(t, rec, 1, "hw.status", "hw.state", "failed", "hw.type", "physical_disk")
	if len(rec.Samples) != 3 {
		t.Fatalf("want 3 series, got %d", len(rec.Samples))
	}
}

func TestRedfishBadPasswordErrorHidesSecrets(t *testing.T) {
	srv := fixtureServer(t)
	rec := &sink.Recorder{}
	err := PollRedfish(context.Background(), Redfish{Name: "bmc1", BaseURL: srv.URL, Username: "monitor", Password: "wrong-pass"}, rec, time.Now())
	if err == nil {
		t.Fatal("a wrong password must fail")
	}
	if strings.Contains(err.Error(), "wrong-pass") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("error leaks: %v", err)
	}
	want(t, rec, 0, "hw.bmc.up")
}

func TestIpmitoolSdrParse(t *testing.T) {
	f, err := os.Open("testdata/sdr_elist.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := ParseSDR(f)
	if err != nil || len(rs) != 7 {
		t.Fatalf("parsed %d lines, %v", len(rs), err)
	}
	if rs[0].Name != "CPU1 Temp" || !rs[0].HasValue || rs[0].Value != 45 || rs[0].Unit != "degrees C" {
		t.Fatalf("first = %+v", rs[0])
	}
	if rs[5].HasValue || rs[5].Status != "ns" {
		t.Fatalf("no-reading line = %+v", rs[5])
	}
	rec := &sink.Recorder{}
	EmitSDR(rec, "local", rs, time.Now())
	want(t, rec, 45, "hw.temperature", "hw.name", "CPU1 Temp")
	want(t, rec, 3840, "hw.fan.speed")
	want(t, rec, 11.2, "hw.voltage")
	want(t, rec, 0.6, "hw.current")
	want(t, rec, 1, "hw.status", "hw.name", "12V", "hw.state", "degraded")
	want(t, rec, 1, "hw.status", "hw.name", "Mem Fault", "hw.state", "failed")
	if _, ok := find(rec, "hw.status", "hw.name", "Intrusion"); ok {
		t.Fatal("an ns sensor says nothing about health")
	}
	if (IPMI{Path: "/definitely/not/here/ipmitool"}).Available() || (IPMI{}).Available() {
		t.Fatal("a missing ipmitool disables the module")
	}
}

func TestNUTListVarParse(t *testing.T) {
	f, err := os.Open("testdata/nut_listvar.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vars, err := ParseListVar(f, "rack")
	if err != nil {
		t.Fatal(err)
	}
	if vars["battery.charge"] != "85" || vars["ups.status"] != "OB LB" || vars["device.model"] != `Smart-UPS "X" 1500` {
		t.Fatalf("vars = %v", vars)
	}
	if len(vars) != 8 {
		t.Fatalf("variables of another UPS must be ignored: %v", vars)
	}
	rec := &sink.Recorder{}
	EmitNUT(rec, NUT{Name: "rack-ups", UPS: "rack"}, vars, time.Now())
	want(t, rec, 0.85, "hw.battery.charge", "hw.ups", "rack-ups")
	want(t, rec, 1260, "hw.battery.time_left")
	want(t, rec, 0.42, "hw.ups.output.load")
	want(t, rec, 310, "hw.power", "hw.power.direction", "output")
	want(t, rec, 1, "hw.ups.on_battery")
	want(t, rec, 1, "hw.battery.low")
	want(t, rec, 0, "hw.battery.replace")
	if _, err := ParseListVar(strings.NewReader("ERR ACCESS-DENIED\n"), "rack"); err == nil {
		t.Fatal("ERR reply must be an error")
	}
}

func TestPollNUTOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	body, _ := os.ReadFile("testdata/nut_listvar.txt")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		if line == "LIST VAR rack\n" {
			_, _ = c.Write(body)
		}
	}()
	rec := &sink.Recorder{}
	n := NUT{Name: "rack-ups", Address: ln.Addr().String(), UPS: "rack"}
	if err := PollNUT(context.Background(), n, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 0.85, "hw.battery.charge")
	n.UPS = "rack\nLOGOUT"
	if PollNUT(context.Background(), n, rec, time.Now()) == nil {
		t.Fatal("a UPS name with a newline must be refused")
	}
}
