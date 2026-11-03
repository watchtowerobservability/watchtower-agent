package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/commands"
	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestLiveFrameRanksByCPUShare(t *testing.T) {
	prev := map[int32]float64{1: 10, 2: 5}
	cur := []commands.ProcessInfo{{PID: 1, Name: "idle", CPUSecs: 10.1, RSS: 9}, {PID: 2, Name: "busy", CPUSecs: 6, RSS: 1}, {PID: 3, Name: "new", CPUSecs: 50}}
	conns := []liveConn{{PID: 2, Proto: "tcp", Status: "LISTEN", Local: "0.0.0.0:80"}, {PID: 2, Proto: "tcp", Status: "ESTABLISHED", Local: "10.0.0.1:80", Remote: "10.0.0.9:5555"}}
	items := liveFrame(prev, cur, conns, 2*time.Second, time.Unix(0, 0))
	if len(items) != 5 || items[0].Attrs["process.executable.name"] != "busy" || items[0].Value != 50 {
		t.Fatalf("%+v", items)
	}
	if items[2].Attrs["process.executable.name"] != "new" || items[2].Value != 0 {
		t.Fatalf("a process without a baseline must show 0: %+v", items[2])
	}
	if items[3].Attrs["network.connection.state"] != "ESTABLISHED" || items[3].Attrs["process.executable.name"] != "busy" {
		t.Fatalf("established connections come first: %+v", items[3])
	}
}

func TestLiveSamplesOnlyWhileTappedAndExportsNothing(t *testing.T) {
	var tp taps
	rec := &sink.Recorder{}
	out := tp.wrap(liveModuleName, rec)
	n := 0.0
	src := liveSource{
		procs: func() ([]commands.ProcessInfo, error) {
			n++
			return []commands.ProcessInfo{{PID: 7, Name: "db", CPUSecs: n}}, nil
		},
		conns: func(context.Context) ([]liveConn, error) { return nil, nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runLive(ctx, json.RawMessage(`{"enabled":true,"interval":"1s"}`), out, src) }()
	b := tp.Run(ctx, liveModuleName, 4)
	var r struct {
		Items []tapItem `json:"items"`
	}
	if err := json.Unmarshal(b, &r); err != nil || len(r.Items) == 0 || r.Items[0].Attrs["process.executable.name"] != "db" {
		t.Fatalf("%s", b)
	}
	if len(rec.Snapshot()) != 0 {
		t.Fatal("live frames must not be exported")
	}
}

func TestLiveIsInertWithoutLocalOptIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	called := false
	src := liveSource{procs: func() ([]commands.ProcessInfo, error) { called = true; return nil, nil }}
	_ = runLive(ctx, nil, (&taps{}).wrap(liveModuleName, &sink.Recorder{}), src)
	if called {
		t.Fatal("sampled without enabled: true")
	}
	if _, err := (liveModule{}).Overlay(nil, json.RawMessage(`{"enabled":true}`)); err == nil {
		t.Fatal("remote config started a module the local file does not define")
	}
}

func TestContainerFrameRanksByCPUAndCarriesPod(t *testing.T) {
	t0 := time.Unix(100, 0)
	prev := map[string]container.Stats{"a": {CPUTotalNS: 0, At: t0}, "b": {CPUTotalNS: 0, At: t0}}
	cur := []liveCtr{
		{Info: container.Info{ID: "a", Name: "idle", State: "running"}, Stats: container.Stats{CPUTotalNS: 1e8, MemUsage: 5, At: t0.Add(time.Second)}},
		{Info: container.Info{ID: "b", Name: "busy", State: "running", Labels: map[string]string{"io.kubernetes.pod.name": "cart-1", "io.kubernetes.pod.namespace": "shop"}},
			Stats: container.Stats{CPUTotalNS: 15e8, MemUsage: 7, At: t0.Add(time.Second)}},
		{Info: container.Info{ID: "c", Name: "new"}, Stats: container.Stats{CPUTotalNS: 9e9, At: t0.Add(time.Second)}},
	}
	rows, next := containerFrame(prev, cur, t0)
	if len(rows) != 3 || rows[0].Attrs["container.name"] != "busy" || rows[0].Value != 150 || rows[1].Value != 10 {
		t.Fatalf("rows %+v", rows)
	}
	if rows[0].Attrs["k8s.pod.name"] != "cart-1" || rows[0].Attrs["k8s.namespace.name"] != "shop" || rows[0].Name != "container.cpu.utilization" {
		t.Fatalf("pod attrs %+v", rows[0])
	}
	if rows[2].Value != 0 || len(next) != 3 {
		t.Fatalf("a container without a baseline shows 0: %+v", rows[2])
	}
}
