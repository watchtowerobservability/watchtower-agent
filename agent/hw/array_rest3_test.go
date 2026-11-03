package hw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func noLeak(t *testing.T, rec *sink.Recorder, secrets ...string) {
	t.Helper()
	for _, s := range rec.Samples {
		for _, v := range s.Attrs {
			for _, x := range secrets {
				if strings.Contains(v, x) {
					t.Fatalf("leak of %q: %v", x, s.Attrs)
				}
			}
		}
	}
}

func TestUnityPoolsLunsAndHealth(t *testing.T) {
	loggedOut := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "mon" || p != "unity-secret" || r.Header.Get("X-EMC-REST-CLIENT") != "true" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/types/loginSessionInfo/instances":
			http.SetCookie(w, &http.Cookie{Name: "mod_sec_emc", Value: "s1", Path: "/"})
			w.Header().Set("EMC-CSRF-TOKEN", "csrf9")
			fmt.Fprint(w, `{"entries":[]}`)
		case "/api/types/loginSessionInfo/action/logout":
			if r.Method == http.MethodPost && r.Header.Get("EMC-CSRF-TOKEN") == "csrf9" {
				loggedOut = true
			}
		case "/api/types/system/instances":
			fmt.Fprint(w, `{"entries":[{"content":{"id":"0","name":"unity1","model":"Unity 480","health":{"value":5}}}]}`)
		case "/api/types/pool/instances":
			fmt.Fprint(w, `{"entries":[{"content":{"id":"pool_1","name":"Pool A","sizeTotal":1000,"sizeUsed":600,"sizeSubscribed":1500,"health":{"value":10}}}]}`)
		case "/api/types/lun/instances":
			fmt.Fprint(w, `{"entries":[{"content":{"id":"sv_1","name":"db","sizeTotal":200,"sizeAllocated":50,"health":{"value":25}}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "u1", Vendor: "unity", BaseURL: srv.URL, Username: "mon", PasswordFile: secretFile(t, "unity-secret"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !loggedOut {
		t.Fatal("session not logged out with the CSRF token")
	}
	want(t, rec, 1, "hw.array.up", "hw.array", "u1", "hw.vendor", "unity")
	want(t, rec, 1, "hw.status", "hw.id", "0", "hw.type", "enclosure", "hw.state", "ok")
	want(t, rec, 1000, "hw.logical_disk.limit", "hw.id", "pool_1")
	want(t, rec, 600, "hw.logical_disk.usage", "hw.id", "pool_1")
	want(t, rec, 1500, "hw.logical_disk.provisioned", "hw.id", "pool_1")
	want(t, rec, 1, "hw.status", "hw.id", "pool_1", "hw.state", "degraded")
	want(t, rec, 50, "hw.logical_disk.usage", "hw.id", "sv_1")
	want(t, rec, 1, "hw.status", "hw.id", "sv_1", "hw.state", "failed")
	noLeak(t, rec, "unity-secret", "csrf9")
}

func TestNimbleTokenPagingAndLogout(t *testing.T) {
	loggedOut := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/tokens" {
			var b struct {
				Data map[string]string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Method != http.MethodPost || b.Data["username"] != "mon" || b.Data["password"] != "nimble-secret" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"data":{"id":"tok1","session_token":"st-1"}}`)
			return
		}
		if r.Header.Get("X-Auth-Token") != "st-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/tokens/tok1":
			loggedOut = r.Method == http.MethodDelete
		case "/v1/arrays/detail":
			fmt.Fprint(w, `{"startRow":0,"endRow":1,"totalRows":1,"data":[{"id":"a1","name":"nim1","status":"unreachable","usable_capacity_bytes":5000,"usage":1200,"model":"AF40"}]}`)
		case "/v1/pools/detail":
			fmt.Fprint(w, `{"totalRows":1,"data":[{"id":"p1","name":"default","capacity":5000,"usage":1200,"free_space":3800}]}`)
		case "/v1/volumes/detail":
			fmt.Fprint(w, `{"totalRows":2,"data":[{"id":"v1","name":"sql","online":true,"size":2,"vol_usage_compressed_bytes":1048576},{"id":"v2","name":"old","online":false,"size":1}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "n1", Vendor: "nimble", BaseURL: srv.URL, Username: "mon", PasswordFile: secretFile(t, "nimble-secret"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !loggedOut {
		t.Fatal("token not deleted")
	}
	want(t, rec, 1, "hw.status", "hw.id", "a1", "hw.type", "enclosure", "hw.state", "failed")
	want(t, rec, 5000, "hw.logical_disk.limit", "hw.id", "a1")
	want(t, rec, 3800, "hw.logical_disk.free", "hw.id", "p1")
	want(t, rec, 2*mibBytes, "hw.logical_disk.limit", "hw.id", "v1")
	want(t, rec, 1048576, "hw.logical_disk.usage", "hw.id", "v1")
	want(t, rec, 1, "hw.status", "hw.id", "v2", "hw.state", "failed")
	noLeak(t, rec, "nimble-secret", "st-1")
}

func TestIBMSpectrumVirtualizeAuthAndCapacity(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/rest/auth" {
			if r.Header.Get("X-Auth-Username") != "mon" || r.Header.Get("X-Auth-Password") != "ibm-secret" {
				http.Error(w, "no", http.StatusForbidden)
				return
			}
			fmt.Fprint(w, `{"token":"t-77"}`)
			return
		}
		if r.Header.Get("X-Auth-Token") != "t-77" || r.Header.Get("X-Auth-Password") != "" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		var opt map[string]any
		_ = json.NewDecoder(r.Body).Decode(&opt)
		switch r.URL.Path {
		case "/rest/lssystem":
			fmt.Fprint(w, `{"name":"fs9200","total_mdisk_capacity":"2.00TB","total_used_capacity":"512.00GB","total_free_space":"1.50TB"}`)
		case "/rest/lsmdiskgrp":
			if opt["bytes"] != true {
				http.Error(w, "want bytes", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `[{"id":"0","name":"Pool0","status":"degraded","capacity":"1000","free_capacity":"400","used_capacity":"600","virtual_capacity":"1800"}]`)
		case "/rest/lsvdisk":
			fmt.Fprint(w, `[{"id":"3","name":"vol3","status":"offline","capacity":"100"}]`)
		case "/rest/lsenclosure":
			fmt.Fprint(w, `[{"id":"1","status":"online","type":"control","product_MTM":"4666-AG8","serial_number":"78E0"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	rec := &sink.Recorder{}
	a := Array{Name: "i1", Vendor: "ibm", BaseURL: srv.URL, Username: "mon", PasswordFile: secretFile(t, "ibm-secret"), InsecureSkipVerify: true}
	if err := PollArray(context.Background(), a, rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	want(t, rec, 2<<40, "hw.logical_disk.limit", "hw.id", "fs9200")
	want(t, rec, 512<<30, "hw.logical_disk.usage", "hw.id", "fs9200")
	want(t, rec, 1000, "hw.logical_disk.limit", "hw.id", "0")
	want(t, rec, 1800, "hw.logical_disk.provisioned", "hw.id", "0")
	want(t, rec, 1, "hw.status", "hw.id", "0", "hw.state", "degraded")
	want(t, rec, 1, "hw.status", "hw.id", "3", "hw.state", "failed")
	want(t, rec, 1, "hw.status", "hw.id", "enclosure1", "hw.type", "enclosure", "hw.state", "ok")
	noLeak(t, rec, "ibm-secret", "t-77")
}

func TestRestRootsPinnedToOrigin(t *testing.T) {
	c := &arrayClient{origin: &url.URL{Scheme: "https", Host: "a.local"}}
	for _, ok := range []string{"/api/types/pool/instances", "/v1/pools/detail", "/rest/lssystem"} {
		if _, err := c.at(ok); err != nil {
			t.Fatalf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"https://evil.example/rest/lssystem", "//evil.example/v1/x", "/etc/passwd", "/rest/../admin"} {
		if _, err := c.at(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	for _, v := range []string{"unity", "nimble", "ibm"} {
		if _, err := newArrayClient(Array{Vendor: v, BaseURL: "https://x"}); err == nil {
			t.Fatalf("%s without username accepted", v)
		}
	}
	if b := ibmBytes("1.5GB"); b == nil || *b != 1.5*(1<<30) {
		t.Fatalf("1.5GB = %v", b)
	}
	if ibmBytes("") != nil || ibmBytes("n/a") != nil {
		t.Fatal("non-sizes parsed")
	}
}
