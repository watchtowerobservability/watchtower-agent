package virt

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmware/govmomi/simulator"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestVSphereDatastoreCapacity(t *testing.T) {
	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	defer model.Remove()
	model.Service.TLS = new(tls.Config)
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
	var capacity, free float64
	var found bool
	for _, s := range rec.Snapshot() {
		a := s.Attrs
		switch s.Name {
		case "vsphere.datastore.capacity":
			found = true
			capacity = s.Value
			if a["resource.datastore.id"] == "" || a["resource.datastore.name"] == "" || a["resource.host.name"] != "" {
				t.Fatalf("datastore resource %v", a)
			}
		case "vsphere.datastore.free":
			free = s.Value
		}
	}
	if !found || capacity <= 0 || free > capacity {
		t.Fatalf("datastore capacity %v free %v found %v", capacity, free, found)
	}
	if dsUUID("ds:///vmfs/volumes/5b0a-11/") != "5b0a-11" {
		t.Fatal("datastore uuid from url")
	}
}

func TestProxmoxStoragePools(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"node":"pve1","status":"online"}]}`))
	})
	mux.HandleFunc("/api2/json/nodes/pve1/storage", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[
			{"storage":"local-lvm","type":"lvmthin","content":"images","active":1,"enabled":1,"shared":0,"total":1000,"used":250,"avail":750},
			{"storage":"ceph","type":"rbd","content":"images","active":1,"enabled":1,"shared":1,"total":4000,"used":1000,"avail":3000},
			{"storage":"nfs-off","type":"nfs","active":0,"enabled":0,"shared":1}]}`))
	})
	for _, k := range []string{"qemu", "lxc"} {
		mux.HandleFunc("/api2/json/nodes/pve1/"+k, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data":[]}`))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rec := &sink.Recorder{}
	if err := PollProxmox(context.Background(), ProxmoxTarget{Name: "c1", URL: srv.URL, TokenID: "t", Secret: "s"}, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := map[string]sink.Sample{}
	for _, s := range rec.Snapshot() {
		if s.Name == "proxmox.storage.utilization" || s.Name == "proxmox.storage.capacity" {
			got[s.Name+"|"+s.Attrs["resource.datastore.id"]] = s
		}
		if s.Attrs["resource.datastore.name"] == "nfs-off" {
			t.Fatal("disabled pool reported")
		}
	}
	local, ok := got["proxmox.storage.utilization|c1/pve1/local-lvm"]
	if !ok || local.Value != 25 || local.Attrs["resource.host.name"] != "pve1" || local.Attrs["resource.datastore.type"] != "lvmthin" {
		t.Fatalf("local pool %+v", local)
	}
	shared, ok := got["proxmox.storage.capacity|c1/ceph"]
	if !ok || shared.Value != 4000 || shared.Attrs["resource.host.name"] != "" {
		t.Fatalf("shared pool must have no host parent: %+v", shared)
	}
}
