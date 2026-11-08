package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterOnTheWrongHostNamesTheFix(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		_, err := NewFleet(srv.URL, "wti_x_y").Register(context.Background(), "", HostInfo{})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "set fleet_endpoint") {
			t.Fatalf("status %d: %v", code, err)
		}
	}
}

func TestRegisterWithAForgottenIDStillAsksToReRegister(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	if _, err := NewFleet(srv.URL, "wti_x_y").Register(context.Background(), "agt_old", HostInfo{}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
