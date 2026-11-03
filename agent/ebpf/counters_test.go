package ebpf

import (
	"testing"
	"time"
)

func TestProfilerCountersReport(t *testing.T) {
	var c ProfilerCounters
	c.UploadsDropped.Add(2)
	got := map[string]float64{}
	c.report(func(n, _ string, v float64, _ map[string]string, _ time.Time) { got[n] = v }, time.Now())
	if got["wt.profiler.uploads_dropped"] != 2 || len(got) != 4 {
		t.Fatal(got)
	}
}
