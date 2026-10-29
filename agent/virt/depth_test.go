package virt

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

func TestNutanixHostsAndVMs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "ro" || p != "pw" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/hosts/"):
			fmt.Fprint(w, `{"entities":[{"name":"ahv1","state":"NORMAL","num_vms":3,"stats":{"hypervisor_cpu_usage_ppm":"250000"}}]}`)
		case strings.Contains(r.URL.Path, "/vms/"):
			fmt.Fprint(w, `{"entities":[{"uuid":"u1","name":"web","power_state":"on","num_vcpus":4,"memory_mb":2048,"host_name":"ahv1","stats":{"hypervisor_cpu_usage_ppm":"500000"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	tg := NutanixTarget{Name: "nx", URL: srv.URL, Username: "ro", Password: "pw"}
	if err := PollNutanix(context.Background(), tg, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]float64{"nutanix.host.cpu.utilization": 25, "nutanix.vm.cpu.utilization": 50, "nutanix.vm.up": 1, "nutanix.vm.cpu.count": 4} {
		var got float64
		var ok bool
		for _, s := range rec.Samples {
			if s.Name == name {
				got, ok = s.Value, true
			}
		}
		if !ok || got != v {
			t.Errorf("%s = %v (found %v), want %v", name, got, ok, v)
		}
	}
}

func TestOpenStackHypervisorsAndServers(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/auth/tokens":
			w.Header().Set("X-Subject-Token", "tok")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":{"catalog":[{"type":"compute","endpoints":[{"interface":"public","region":"r1","url":%q}]}]}}`, srv.URL+"/compute")
		case "/compute/os-hypervisors/detail":
			fmt.Fprint(w, `{"hypervisors":[{"hypervisor_hostname":"cn1","state":"up","status":"enabled","vcpus":32,"vcpus_used":8,"memory_mb":1024,"memory_mb_used":512,"running_vms":2}]}`)
		case "/compute/servers/detail":
			if r.Header.Get("X-Auth-Token") != "tok" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"servers":[{"id":"s1","name":"vm1","status":"ACTIVE","OS-EXT-SRV-ATTR:host":"cn1"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	tg := OpenStackTarget{Name: "os", AuthURL: srv.URL, Username: "u", Password: "pw", Project: "p"}
	if err := PollOpenStack(context.Background(), tg, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	names := rec.Names()
	if !names["openstack.hypervisor.up"] || !names["openstack.server.up"] {
		t.Fatalf("missing series: %v", names)
	}
}

func TestParseDomstats(t *testing.T) {
	ds := ParseDomstats("Domain: 'vm1'\n  state.state=1\n  balloon.current=2048\n\nDomain: 'vm2'\n  state.state=5\n")
	if len(ds) != 2 || ds[0].Name != "vm1" || ds[0].Num["balloon.current"] != 2048 || ds[1].Num["state.state"] != 5 {
		t.Fatalf("bad parse %+v", ds)
	}
}

func TestTargetsRefuseCredentialsOverPlainHTTP(t *testing.T) {
	if err := (NutanixTarget{Name: "n", Username: "u", URL: "http://prism.example:9440"}).validate(); err == nil {
		t.Fatal("plain http to a non-loopback host must be refused")
	}
}
