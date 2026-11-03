package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNoProxyMatch(t *testing.T) {
	list := []string{".internal.example", "otlp.local"}
	for host, want := range map[string]bool{
		"a.internal.example": true, "internal.example": true, "otlp.local": true,
		"x.otlp.local": true, "example.com": false, "notinternal.example": false,
	} {
		if got := noProxyMatch(host, list); got != want {
			t.Errorf("%s: got %v", host, got)
		}
	}
	if !noProxyMatch("anything", []string{"*"}) {
		t.Error("* bypasses every host")
	}
}

func TestForwardThroughProxyUnlessNoProxy(t *testing.T) {
	var proxied atomic.Int32
	// A plain-HTTP forward proxy sees the absolute target URL in the request line.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.RequestURI, "http://otlp.example.test/") {
			proxied.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()
	ctx := context.Background()
	c, err := forwardClient(ctx, ForwardTarget{Proxy: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post("http://otlp.example.test/v1/logs", "application/x-protobuf", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if proxied.Load() != 1 {
		t.Fatalf("request did not go through the proxy")
	}
	if _, err := forwardClient(ctx, ForwardTarget{Proxy: "ftp://proxy:21"}); err == nil {
		t.Fatal("a non-http proxy URL must be refused")
	}
	direct, _ := forwardClient(ctx, ForwardTarget{Proxy: proxy.URL, NoProxy: []string{"example.test"}})
	if _, err := direct.Post("http://otlp.example.test/v1/logs", "application/x-protobuf", strings.NewReader("x")); err == nil {
		t.Fatal("no_proxy host must be dialled directly (and does not resolve here)")
	}
	if proxied.Load() != 1 {
		t.Fatal("no_proxy host went through the proxy")
	}
}
