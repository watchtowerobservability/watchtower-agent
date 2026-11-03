package hw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const smartJSON = `{"device":{"name":"/dev/sda","type":"sat"},"model_name":"WDC WD40","serial_number":"WX1",
"smart_status":{"passed":false},"temperature":{"current":41},"power_on_time":{"hours":100},
"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":12}},{"id":9,"raw":{"value":100}},{"id":197,"raw":{"value":3}}]}}`

func TestSmartctlJSONBecomesDiskHealth(t *testing.T) {
	rec := &sink.Recorder{}
	if err := EmitSmart(rec, map[string]string{"hw.ssh": "srv1"}, "/dev/sda", []byte(smartJSON), time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "hw.status", "hw.id", "/dev/sda", "hw.type", "physical_disk", "hw.state", "failed")
	want(t, rec, 41, "hw.temperature", "hw.id", "/dev/sda")
	want(t, rec, 360000, "hw.physical_disk.power_on_time", "hw.id", "/dev/sda")
	want(t, rec, 12, "hw.physical_disk.smart", "hw.smart.attribute", "reallocated_sectors")
	want(t, rec, 3, "hw.physical_disk.smart", "hw.smart.attribute", "pending_sectors")
	n := 0
	for _, s := range rec.Samples {
		if s.Name == "hw.physical_disk.smart" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want only the 2 listed SMART attributes, got %d", n)
	}
	if err := EmitSmart(rec, nil, "/dev/sdb", []byte("smartctl: not found"), time.Now()); err == nil {
		t.Fatal("non-JSON output accepted")
	}
}

func TestNVMeSmartLogKelvinAndWear(t *testing.T) {
	rec := &sink.Recorder{}
	b := []byte(`{"critical_warning":0,"temperature":310,"avail_spare":100,"percent_used":7,"media_errors":0,"unsafe_shutdowns":4}`)
	if err := EmitNVMe(rec, nil, "/dev/nvme0", b, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "hw.status", "hw.id", "/dev/nvme0", "hw.state", "ok")
	want(t, rec, 36.85, "hw.temperature", "hw.id", "/dev/nvme0")
	want(t, rec, 0.07, "hw.physical_disk.endurance_utilization")
	want(t, rec, 1, "hw.physical_disk.spare_ratio")
	want(t, rec, 4, "hw.physical_disk.unsafe_shutdowns")
}

const mdstat = `Personalities : [raid1] [raid6]
md0 : active raid1 sdb1[1] sda1[0]
      976630464 blocks super 1.2 [2/2] [UU]

md1 : active raid6 sdc[0] sdd[1] sde[2](F) sdf[3]
      1953260544 blocks super 1.2 level 6, 512k chunk, algorithm 2 [4/3] [UU_U]
      [=>...................]  recovery = 8.4% (82000/976630272) finish=90.1min speed=150000K/sec

md2 : inactive sdg[0](S)
      976630464 blocks

unused devices: <none>
`

func TestMDStatStates(t *testing.T) {
	arrs := ParseMDStat(mdstat)
	if len(arrs) != 3 || arrs[1].Level != "raid6" || arrs[1].Up != 3 || !arrs[1].Rebuilding {
		t.Fatalf("%+v", arrs)
	}
	rec := &sink.Recorder{}
	EmitMDStat(rec, nil, arrs, time.Now())
	want(t, rec, 1, "hw.status", "hw.id", "md0", "hw.state", "ok")
	want(t, rec, 1, "hw.status", "hw.id", "md1", "hw.state", "degraded")
	want(t, rec, 1, "hw.status", "hw.id", "md2", "hw.state", "failed")
	want(t, rec, 0.084, "hw.logical_disk.rebuild_progress", "hw.id", "md1")
	want(t, rec, 3, "hw.logical_disk.members_up", "hw.id", "md1")
}

func TestSSHDevicePathsRefuseShellText(t *testing.T) {
	ok := SSHHost{Name: "s", Host: "h", User: "u", Disks: []string{"/dev/sda", "/dev/disk/by-id/ata-X_1"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/dev/sda; rm -rf /", "/dev/../etc/shadow", "sda", "/dev/sd a", "/dev/$(id)"} {
		h := ok
		h.Disks = []string{bad}
		if h.Validate() == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if (SSHHost{Name: "s", Host: "h", User: "u", Sudo: true}).cmd("smartctl", "-j", "/dev/sda") != "sudo -n smartctl -j /dev/sda" {
		t.Fatal("sudo prefix")
	}
}

func secretFile(t *testing.T, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestONTAPAggregatesVolumesDisks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "mon" || p != "ontap-secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/storage/aggregates" && r.URL.Query().Get("page") == "":
			_, _ = w.Write([]byte(`{"records":[{"name":"aggr1","state":"online","space":{"block_storage":{"size":1000,"used":400}}}],
				"_links":{"next":{"href":"/api/storage/aggregates?page=2"}}}`))
		case r.URL.Path == "/api/storage/aggregates":
			_, _ = w.Write([]byte(`{"records":[{"name":"aggr2","state":"offline","space":{"block_storage":{"size":10,"used":1}}}]}`))
		case r.URL.Path == "/api/storage/volumes":
			_, _ = w.Write([]byte(`{"records":[{"name":"vol1","state":"online","svm":{"name":"svm1"},"space":{"size":500,"used":250}}]}`))
		case r.URL.Path == "/api/storage/disks":
			_, _ = w.Write([]byte(`{"records":[{"name":"1.0.1","state":"broken","model":"X"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "na1", Vendor: "ontap", BaseURL: srv.URL, Username: "mon", PasswordFile: secretFile(t, "ontap-secret"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 1, "hw.array.up", "hw.array", "na1")
	want(t, rec, 400, "hw.logical_disk.usage", "hw.id", "aggr1")
	want(t, rec, 1, "hw.status", "hw.id", "aggr2", "hw.state", "failed")
	want(t, rec, 500, "hw.logical_disk.limit", "hw.id", "svm1/vol1")
	want(t, rec, 1, "hw.status", "hw.id", "1.0.1", "hw.type", "physical_disk", "hw.state", "failed")
	for _, s := range rec.Samples {
		for _, v := range s.Attrs {
			if strings.Contains(v, "ontap-secret") || strings.Contains(v, srv.URL) {
				t.Fatalf("leak: %v", s.Attrs)
			}
		}
	}
}

func TestArrayNextLinkLeavingOriginRefused(t *testing.T) {
	c := &arrayClient{origin: &url.URL{Scheme: "https", Host: "array.local"}}
	if _, err := c.at("https://evil.example/api/storage/volumes"); err == nil {
		t.Fatal("absolute link accepted")
	}
	if _, err := c.at("//evil.example/api/x"); err == nil {
		t.Fatal("scheme-relative link accepted")
	}
	if u, err := c.at("/api/storage/volumes?page=2"); err != nil || u != "https://array.local/api/storage/volumes?page=2" {
		t.Fatalf("%q %v", u, err)
	}
}

func TestPureLoginThenSpaceAndHardware(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/2.4/login" {
			if r.Method != http.MethodPost || r.Header.Get("api-token") != "pure-token" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			w.Header().Set("x-auth-token", "sess")
			return
		}
		if r.Header.Get("x-auth-token") != "sess" || r.Header.Get("api-token") != "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/2.4/arrays/space":
			_, _ = w.Write([]byte(`{"items":[{"name":"fa1","capacity":2000,"space":{"total_physical":500,"data_reduction":3.5}}]}`))
		case "/api/2.4/volumes":
			_, _ = w.Write([]byte(`{"items":[{"name":"db","provisioned":100,"space":{"virtual":40}}]}`))
		case "/api/2.4/hardware":
			_, _ = w.Write([]byte(`{"items":[{"name":"CH0.BAY1","type":"drive_bay","status":"critical"},{"name":"CH0.PWR0","type":"power_supply","status":"ok"},{"name":"CH0.BAY9","type":"drive_bay","status":"not_installed"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "pure1", Vendor: "pure", BaseURL: srv.URL, APITokenFile: secretFile(t, "pure-token"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 2000, "hw.logical_disk.limit", "hw.id", "fa1")
	want(t, rec, 3.5, "hw.array.data_reduction", "hw.id", "fa1")
	want(t, rec, 40, "hw.logical_disk.usage", "hw.id", "db")
	want(t, rec, 1, "hw.status", "hw.id", "CH0.BAY1", "hw.type", "physical_disk", "hw.state", "failed")
	want(t, rec, 1, "hw.status", "hw.id", "CH0.PWR0", "hw.type", "power_supply", "hw.state", "ok")
	if _, ok := find(rec, "hw.status", "hw.id", "CH0.BAY9"); ok {
		t.Fatal("empty bay reported")
	}
}

func TestArrayNeedsHTTPSAndKnownVendor(t *testing.T) {
	for _, a := range []Array{{Vendor: "ontap", BaseURL: "http://x", Username: "u"}, {Vendor: "emc", BaseURL: "https://x"}} {
		if _, err := newArrayClient(a); err == nil {
			t.Fatalf("%+v accepted", a)
		}
	}
}
