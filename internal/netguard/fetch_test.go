package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestFetchRefusesPrivateAndNonHTTPS(t *testing.T) {
	ctx := context.Background()
	if _, err := Fetch(ctx, "http://example.com/a.ics", FetchOptions{}); err == nil {
		t.Fatal("http accepted")
	}
	// A local listener is a private address: the dialer refuses it at connect.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := Fetch(ctx, srv.URL, FetchOptions{}); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func TestFetchETagAndCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	local := Options{Block: func(netip.Addr) bool { return false }}
	got, err := fetch(context.Background(), u, FetchOptions{Options: local})
	if err != nil || got.ETag != `"v1"` || len(got.Body) != 100 {
		t.Fatalf("fetch: %+v %v", got, err)
	}
	got, err = fetch(context.Background(), u, FetchOptions{ETag: `"v1"`, Options: local})
	if err != nil || !got.NotModified || got.Body != nil {
		t.Fatalf("304: %+v %v", got, err)
	}
	if _, err = fetch(context.Background(), u, FetchOptions{MaxBytes: 10, Options: local}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("cap: %v", err)
	}
}
