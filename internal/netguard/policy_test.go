package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAirgapDeniesUnlistedHost(t *testing.T) {
	before := DeniedTotal()["other"]
	c := NewClient(Policy{DenyAll: true, AllowPrivate: true, Purpose: "an-unbounded-label-longer-than-thirty-two-bytes"})
	_, err := c.Get("http://phone-home.example.invalid/")
	var d *ErrEgressDenied
	if !errors.As(err, &d) || d.Host != "phone-home.example.invalid" {
		t.Fatalf("want ErrEgressDenied, got %v", err)
	}
	if DeniedTotal()["other"] != before+1 {
		t.Fatal("denied counter did not move under the bounded label")
	}
}

func TestAirgapAllowsListedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := NewClient(Policy{DenyAll: true, AllowPrivate: true, AllowHosts: []string{u.Hostname()}, Purpose: "api"})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestPrivateRangesStillBlockedUnlessPolicyAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := NewClient(Policy{}).Get(srv.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("private target must be blocked, got %v", err)
	}
	resp, err := NewClient(Policy{AllowPrivate: true}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestFromEnv(t *testing.T) {
	t.Setenv("WT_AIRGAP", "")
	if FromEnv("api").DenyAll {
		t.Fatal("deny-all without WT_AIRGAP")
	}
	t.Setenv("WT_AIRGAP", "1")
	t.Setenv("WT_EGRESS_ALLOW", "ch.internal, *.corp.example")
	p := FromEnv("api")
	if !p.DenyAll || !p.HostAllowed("ch.internal") || !p.HostAllowed("a.corp.example") || p.HostAllowed("evil.com") {
		t.Fatalf("bad policy %+v", p)
	}
}
