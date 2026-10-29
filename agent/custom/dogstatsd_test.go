package custom

import (
	"testing"
	"time"
)

func TestDogStatsDSampleRateScalesCounter(t *testing.T) {
	d := NewDogStatsD()
	d.Feed("hits:1|c|@0.1|#env:prod,canary\nhits:2|c|#env:prod,canary")
	rc := &rec{}
	d.Flush(rc, time.Now())
	s, ok := rc.find("sum", "hits", map[string]string{"env": "prod", "canary": "true"})
	if !ok || s.value != 12 { // 1/0.1 + 2
		t.Fatalf("counter = %+v (ok=%v), want 12: %+v", s, ok, rc.s)
	}
}

func TestDogStatsDTypesAndIgnored(t *testing.T) {
	d := NewDogStatsD()
	d.Feed("g1:5|g\ng1:7|g\nt:10:20:30|ms|@0.5\nu:a|s\nu:b|s\nu:a|s\n_e{5,4}:title|text\n_sc|check|0\nbad line\nx:abc|g")
	rc := &rec{}
	d.Flush(rc, time.Now())
	checks := []struct {
		kind, name string
		want       float64
	}{
		{"gauge", "g1", 7}, {"gauge", "u", 2}, {"sum", "t.count", 6}, {"gauge", "t.avg", 20},
		{"gauge", "t.min", 10}, {"gauge", "t.max", 30},
		{"sum", "wt_dogstatsd_ignored_total", 2}, {"sum", "wt_dogstatsd_invalid_total", 2},
	}
	for _, c := range checks {
		if s, ok := rc.find(c.kind, c.name, nil); !ok || s.value != c.want {
			t.Errorf("%s %s = %+v (ok=%v), want %v", c.kind, c.name, s, ok, c.want)
		}
	}
}
