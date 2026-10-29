package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/internal/wal"
)

// gateway is a test double that answers 503 while down and records every metric name it accepts.
type gateway struct {
	down atomic.Bool
	mu   sync.Mutex
	seen map[string]bool
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	b, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/v1/metrics" {
		var req colmetrics.ExportMetricsServiceRequest
		if proto.Unmarshal(b, &req) == nil {
			g.mu.Lock()
			for _, rm := range req.ResourceMetrics {
				for _, sm := range rm.ScopeMetrics {
					for _, m := range sm.Metrics {
						g.seen[m.Name] = true
					}
				}
			}
			g.mu.Unlock()
		}
	}
	w.WriteHeader(http.StatusOK)
}

func TestExportDownThenRecoverNoLoss(t *testing.T) {
	gw := &gateway{seen: map[string]bool{}}
	gw.down.Store(true)
	srv := httptest.NewServer(gw)
	defer srv.Close()
	w, err := wal.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	o := NewOTLP(srv.URL, "wti_x_y", nil)
	o.Buffer = w
	const rounds = 5
	for i := range rounds { // outage: each flush fails and spills to disk, memory empties
		o.Gauge(fmt.Sprintf("outage_metric_%d", i), "", float64(i), nil, time.Now())
		if err := o.Flush(context.Background()); err == nil {
			t.Fatal("flush must report the outage")
		}
	}
	if w.Count() != rounds || o.pending() != 0 {
		t.Fatalf("want %d batches on disk and none in memory, got %d / %d", rounds, w.Count(), o.pending())
	}
	gw.down.Store(false)
	o.Gauge("after_recovery", "", 1, nil, time.Now())
	if err := o.Flush(context.Background()); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	for i := range rounds {
		if n := fmt.Sprintf("outage_metric_%d", i); !gw.seen[n] {
			t.Fatalf("%s lost across the outage", n)
		}
	}
	if !gw.seen["after_recovery"] || w.Count() != 0 {
		t.Fatalf("new data delivered=%v, disk batches left=%d", gw.seen["after_recovery"], w.Count())
	}
}

func TestBufferWhenFullDropNewest(t *testing.T) {
	w, err := wal.Open(t.TempDir(), 1) // 1 byte: the first 16 MiB segment already fills it
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() // Windows cannot remove the temp dir while the segment is open
	w.DropNewest = true
	big := make([]byte, 1<<20)
	var refused bool
	for range 40 { // 40 MiB offered, at most a couple of segments accepted
		if err := w.Append(big); err != nil {
			refused = err == wal.ErrFull
			break
		}
	}
	if !refused {
		t.Fatal("a full drop_newest queue must refuse with ErrFull")
	}
	if w.Dropped() != 0 {
		t.Fatal("drop_newest must not discard stored segments")
	}
}
