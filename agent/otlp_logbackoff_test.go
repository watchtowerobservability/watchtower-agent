package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefusedLogsDoNotDelayMetrics(t *testing.T) {
	var metrics, logs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/logs") {
			logs.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		metrics.Add(1)
	}))
	defer srv.Close()
	o := NewOTLP(srv.URL, "t", nil)
	for range 2 {
		o.Gauge("m", "1", 1, nil, time.Now())
		o.Log("INFO", "x", nil, time.Now())
		if err := o.Flush(context.Background()); err != nil {
			t.Fatalf("a refused log batch must not fail the flush: %v", err)
		}
	}
	if metrics.Load() != 2 {
		t.Fatalf("metrics posts = %d, want 2", metrics.Load())
	}
	if logs.Load() != 1 {
		t.Fatalf("logs posts = %d, want 1 (backing off)", logs.Load())
	}
	if len(o.logs) != 2 {
		t.Fatalf("kept %d log records, want 2", len(o.logs))
	}
}
