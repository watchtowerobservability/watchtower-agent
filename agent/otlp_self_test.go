package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelfStatsCountDeliveryOutcomes(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	o := NewOTLP(srv.URL, "tok", map[string]string{"service.name": "wt-agent"})
	ctx := context.Background()
	if _, err := o.send(ctx, "/v1/logs", []byte("abc")); err != nil {
		t.Fatal(err)
	}
	status = http.StatusBadRequest
	_, _ = o.send(ctx, "/v1/logs", []byte("x"))
	status = http.StatusServiceUnavailable
	_, _ = o.send(ctx, "/v1/logs", []byte("x"))
	st := (&tapExporter{module: "agent", Exporter: o, t: &taps{}}).SelfStats()
	for k, want := range map[string]float64{
		"wt_agent_export_batches_sent_total": 1, "wt_agent_export_batches_rejected_total": 1,
		"wt_agent_export_batches_failed_total": 1, "wt_agent_export_bytes_sent_total": 3,
	} {
		if st[k] != want {
			t.Errorf("%s = %v, want %v", k, st[k], want)
		}
	}
}
