package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

type countModule struct {
	mu      *sync.Mutex
	running map[string]int
	name    string
}

func (countModule) Name() string { return "count" }
func (c countModule) Start(ctx context.Context, _ json.RawMessage, _ Exporter) error {
	c.mu.Lock()
	c.running[c.name]++
	c.mu.Unlock()
	<-ctx.Done()
	c.mu.Lock()
	c.running[c.name]--
	c.mu.Unlock()
	return nil
}

func TestClusterChecksRunOnlyWhereOwnedAndMove(t *testing.T) {
	var mu sync.Mutex
	running := map[string]int{}
	cs := []clusterCheck{{Name: "db"}, {Name: "api"}}
	mods := map[string]Module{"db": countModule{&mu, running, "db"}, "api": countModule{&mu, running, "api"}}
	var ownMu sync.Mutex
	mine := map[string]bool{"db": true}
	owns := func(k string) bool { ownMu.Lock(); defer ownMu.Unlock(); return mine[k] }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go dispatch(ctx, 20*time.Millisecond, cs, mods, owns, &sink.Recorder{})
	wait := func(want map[string]int) {
		t.Helper()
		for range 200 {
			mu.Lock()
			ok := running["db"] == want["db"] && running["api"] == want["api"]
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("running %v, want %v", running, want)
	}
	wait(map[string]int{"db": 1, "api": 0})
	ownMu.Lock()
	mine = map[string]bool{"api": true}
	ownMu.Unlock()
	wait(map[string]int{"db": 0, "api": 1})
}

func TestClusterChecksRefuseNonCheckModules(t *testing.T) {
	m := NewRegistry(&LocalConfig{StateDir: t.TempDir()})["cluster_checks"].(clusterChecksModule)
	if _, err := m.resolve([]clusterCheck{{Name: "x", Module: "logs"}}); err == nil {
		t.Fatal("logs must not run as a cluster check")
	}
	if _, err := m.resolve([]clusterCheck{{Name: "pg", Module: "postgres"}, {Name: "pg", Module: "redis"}}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if _, err := m.resolve([]clusterCheck{{Name: "pg", Module: "postgres"}, {Name: "web", Module: "prometheus"}}); err != nil {
		t.Fatal(err)
	}
}
