package ebpf

import (
	"context"
	"sync/atomic"
	"time"
)

// Counters are the profiler's own health (CFT-E18), cumulative since the agent started.
var Counters ProfilerCounters

// ProfilerCounters counts profile uploads and what went wrong on the way.
type ProfilerCounters struct {
	Uploads, UploadsDropped, FoldFailures, DrainFailures atomic.Uint64
}

// Export reports the counters every 30 s until ctx ends.
func (c *ProfilerCounters) Export(ctx context.Context, sum func(name, unit string, v float64, attrs map[string]string, at time.Time)) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.report(sum, now)
		}
	}
}

func (c *ProfilerCounters) report(sum func(string, string, float64, map[string]string, time.Time), at time.Time) {
	attrs := map[string]string{"module": "ebpf_profiler"}
	sum("wt.profiler.uploads", "{profile}", float64(c.Uploads.Load()), attrs, at)
	sum("wt.profiler.uploads_dropped", "{profile}", float64(c.UploadsDropped.Load()), attrs, at)
	sum("wt.profiler.fold_failures", "{failure}", float64(c.FoldFailures.Load()), attrs, at)
	sum("wt.profiler.drain_failures", "{failure}", float64(c.DrainFailures.Load()), attrs, at)
}
