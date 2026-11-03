package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestForwardOTLPCopyWithAuth(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+"|"+r.Header.Get("Authorization")+"|"+r.Header.Get("X-Key")+"|"+string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	t.Setenv("WT_FWD_KEY", "k1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs, err := StartForwarders(ctx, []ForwardTarget{{Kind: "otlp_http", Endpoint: srv.URL, Signals: []string{"logs"},
		Headers: map[string]string{"X-Key": "${env:WT_FWD_KEY}"}, Bearer: "tok"}})
	if err != nil {
		t.Fatal(err)
	}
	fs[0].hc = srv.Client()
	fs.Tee("/v1/metrics", []byte("m")) // not subscribed
	fs.Tee("/v1/logs", []byte("l"))
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "/v1/logs|Bearer tok|k1|l" {
		t.Fatalf("forwarded %v", got)
	}
	if _, err := StartForwarders(ctx, []ForwardTarget{{Kind: "splunk"}}); err == nil {
		t.Fatal("unknown kind must fail")
	}
}
