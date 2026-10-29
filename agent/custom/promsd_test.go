package custom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPAndConsulSD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/targets":
			fmt.Fprint(w, `[{"targets":["10.0.0.1:9100","10.0.0.2:9100"],"labels":{"env":"prod"}}]`)
		case "/v1/catalog/services":
			fmt.Fprint(w, `{"web":["a"],"consul":[]}`)
		case "/v1/catalog/service/web":
			fmt.Fprint(w, `[{"Node":"n1","Address":"10.1.0.1","ServiceAddress":"","ServicePort":8080,"ServiceTags":["a"],"Datacenter":"dc1"}]`)
		case "/v1/catalog/service/consul":
			fmt.Fprint(w, `[{"Node":"n1","Address":"10.1.0.1","ServicePort":0}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	got, err := SDConfig{Type: "http", URL: srv.URL + "/targets"}.discover(ctx, srv.Client())
	if err != nil || len(got) != 2 || got[0].URL != "http://10.0.0.1:9100/metrics" || got[0].Labels["env"] != "prod" {
		t.Fatalf("http sd: %v %v", got, err)
	}
	got, err = SDConfig{Type: "consul", URL: srv.URL}.discover(ctx, srv.Client())
	if err != nil || len(got) != 1 || got[0].URL != "http://10.1.0.1:8080/metrics" || got[0].Labels["consul_service"] != "web" {
		t.Fatalf("consul sd (portless entries skipped): %v %v", got, err)
	}
}

func TestSDValidateAndRemoteRejected(t *testing.T) {
	if (SDConfig{Type: "dns", Names: []string{"x"}}).validate() == nil {
		t.Fatal("dns A without port must fail")
	}
	if (SDConfig{Type: "http", URL: "file:///etc/passwd"}).validate() == nil {
		t.Fatal("non-http sd url must fail")
	}
	_, err := Prometheus{}.Overlay(nil, []byte(`{"sd_configs":[{"type":"http","url":"http://x"}]}`))
	if err == nil {
		t.Fatal("remote config must not add sd_configs")
	}
}

func TestShardingSplitsTargetsExactlyOnce(t *testing.T) {
	const total = 3
	owned := map[string]int{}
	for i := range 60 {
		u := fmt.Sprintf("http://10.0.0.%d:9100/metrics", i)
		for idx := range total {
			if inShard(u, total, idx) {
				owned[u]++
			}
		}
	}
	for u, n := range owned {
		if n != 1 {
			t.Fatalf("%s owned by %d agents", u, n)
		}
	}
	if len(owned) != 60 || !inShard("http://x", 0, 0) {
		t.Fatalf("every target needs exactly one owner (%d), and total<=1 keeps all", len(owned))
	}
}

func TestStaleMarkerOnFailingTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := &rec{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Prometheus{}.loop(ctx, TargetSpec{URL: srv.URL, ScrapeInterval: "5s"}, r)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, s := range r.s {
			if s.name == "wt_scrape_stale" && s.value == 1 {
				r.mu.Unlock()
				return
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no staleness marker for a failing target")
}
