package virt

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vmware/govmomi/simulator"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestVSphereSimulator(t *testing.T) {
	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	defer model.Remove()
	model.Service.TLS = new(tls.Config) // the simulator serves plain HTTP unless given a TLS config
	s := model.Service.NewServer()
	defer s.Close()
	pw, _ := s.URL.User.Password()
	target := VSphereTarget{Name: "sim", URL: "https://" + s.URL.Host + s.URL.Path, Username: s.URL.User.Username(), Password: pw, Insecure: true}
	rec := &sink.Recorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := PollVSphere(ctx, target, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	names := rec.Names()
	if !names["vsphere.vm.info"] {
		t.Fatalf("no VM inventory: %v", names)
	}
	var sawVM bool
	for _, s := range rec.Snapshot() {
		if s.Name == "vsphere.vm.info" {
			sawVM = s.Attrs["resource.vm.id"] != "" && s.Attrs["resource.host.name"] != ""
		}
		for k, v := range s.Attrs {
			if strings.Contains(k+v+s.Body, pw) {
				t.Fatal("password leaked")
			}
		}
	}
	if !sawVM {
		t.Fatal("vm entity lacks id or parent host")
	}
}

func TestProxmoxFixture(t *testing.T) {
	const token = "SECRETVALUE"
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken=root@pam!wt="+token {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"node":"pve1","status":"online","cpu":0.25,"mem":100,"maxmem":200,"uptime":5}]}`))
	})
	mux.HandleFunc("/api2/json/nodes/pve1/qemu", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"vmid":100,"name":"web","status":"running","cpu":0.5,"cpus":2,"mem":1,"maxmem":2,"uptime":9,"netin":3,"netout":4,"diskread":5,"diskwrite":6}]}`))
	})
	mux.HandleFunc("/api2/json/nodes/pve1/storage", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	mux.HandleFunc("/api2/json/nodes/pve1/lxc", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"vmid":"200","name":"ct","status":"stopped","cpu":0,"cpus":1,"mem":0,"maxmem":2}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rec := &sink.Recorder{}
	tg := ProxmoxTarget{Name: "c1", URL: srv.URL, TokenID: "root@pam!wt", Secret: token}
	if err := PollProxmox(context.Background(), tg, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	vals := map[string]sink.Sample{}
	for _, s := range rec.Snapshot() {
		vals[s.Name] = s
	}
	if vals["proxmox.qemu.cpu.utilization"].Value != 50 || vals["proxmox.qemu.up"].Value != 1 || vals["proxmox.lxc.up"].Value != 0 || vals["proxmox.qemu.cpu.count"].Value != 2 || vals["proxmox.lxc.cpu.count"].Value != 1 {
		t.Fatalf("%+v", vals)
	}
	if a := vals["proxmox.qemu.up"].Attrs; a["resource.vm.id"] != "c1/100" || a["resource.host.name"] != "pve1" || a["resource.os.type"] != "" || a["resource.host.id"] != "" {
		t.Fatalf("%v", a)
	}

	tg.Secret = "wrong"
	err := PollProxmox(context.Background(), tg, rec, time.Now())
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("want a redacted failure: %v", err)
	}
	if (ProxmoxTarget{URL: "http://pve.example:8006"}).validate() == nil {
		t.Fatal("plain http to a non-loopback host must be refused")
	}
}

func TestHypervisorHostIdentity(t *testing.T) {
	r, own := hypervisorHost("some-other-hypervisor.example")
	if own || r["host.name"] != "some-other-hypervisor.example" || r["os.type"] != "" || r["host.id"] != "" {
		t.Fatalf("%v %v", r, own)
	}
	h, _ := os.Hostname()
	if r, own := hypervisorHost(h); !own || len(r) != 1 || r["host.name"] != h {
		t.Fatalf("the agent's own host must keep the agent's resource: %v %v", r, own)
	}
}
