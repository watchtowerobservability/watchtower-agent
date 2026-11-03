package main

// Live containers (INF-022, Datadog Live Containers): while a live_processes tap is open, every
// frame also carries the busiest containers with CPU %, memory, state and the Kubernetes pod the
// runtime labels them with. Docker only; with no reachable engine the frame has no container rows.

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
)

const liveContainers = 20

// liveCtr is one container sample.
type liveCtr struct {
	Info  container.Info
	Stats container.Stats
}

// dockerLive lists running containers with one stats sample each (8 in parallel).
func dockerLive(host string) func(ctx context.Context) ([]liveCtr, error) {
	var d *container.Docker
	return func(ctx context.Context) ([]liveCtr, error) {
		if d == nil {
			if host == "" {
				host = container.DefaultHost()
			}
			dd, err := container.NewDocker(host)
			if err != nil {
				return nil, err
			}
			d = dd
		}
		list, err := d.List(ctx)
		if err != nil {
			return nil, err
		}
		var mu sync.Mutex
		out := make([]liveCtr, 0, len(list))
		var g errgroup.Group
		g.SetLimit(8)
		for _, c := range list {
			g.Go(func() error {
				st, err := d.Stats(ctx, c.ID)
				if err != nil {
					return nil // exited between list and stats
				}
				mu.Lock()
				out = append(out, liveCtr{Info: c, Stats: st})
				mu.Unlock()
				return nil
			})
		}
		_ = g.Wait()
		return out, nil
	}
}

// containerFrame ranks containers by CPU share since prev (container id -> cumulative ns at the
// previous sample) and returns the tap rows plus the new baselines.
func containerFrame(prev map[string]container.Stats, cur []liveCtr, at time.Time) ([]tapItem, map[string]container.Stats) {
	type row struct {
		c   liveCtr
		pct float64
	}
	next := make(map[string]container.Stats, len(cur))
	rows := make([]row, 0, len(cur))
	for _, c := range cur {
		next[c.Info.ID] = c.Stats
		pct := 0.0
		if old, ok := prev[c.Info.ID]; ok && c.Stats.At.After(old.At) && c.Stats.CPUTotalNS >= old.CPUTotalNS {
			pct = float64(c.Stats.CPUTotalNS-old.CPUTotalNS) / float64(c.Stats.At.Sub(old.At).Nanoseconds()) * 100
		}
		rows = append(rows, row{c, pct})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].pct != rows[j].pct {
			return rows[i].pct > rows[j].pct
		}
		return rows[i].c.Stats.MemUsage > rows[j].c.Stats.MemUsage
	})
	ms := at.UnixMilli()
	out := make([]tapItem, 0, min(len(rows), liveContainers))
	for _, r := range rows[:min(len(rows), liveContainers)] {
		i := r.c.Info
		a := map[string]string{"container.id": i.ID, "container.name": i.Name, "container.image.name": i.Image,
			"container.state": i.State, "container.memory.usage": strconv.FormatUint(r.c.Stats.MemUsage, 10)}
		// cri-dockerd and dockershim label pod containers with their pod
		if v := i.Labels["io.kubernetes.pod.name"]; v != "" {
			a["k8s.pod.name"], a["k8s.namespace.name"] = v, i.Labels["io.kubernetes.pod.namespace"]
		}
		out = append(out, tapItem{At: ms, Kind: "gauge", Name: "container.cpu.utilization", Value: r.pct, Attrs: a})
	}
	return out, next
}
