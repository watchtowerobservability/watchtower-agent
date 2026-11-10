package custom

import (
	"strconv"
	"strings"
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
		{"sum", "wt_dogstatsd_ignored_total", 1}, {"sum", "wt_dogstatsd_invalid_total", 2},
		{"gauge", "datadog.check_run.status", 0},
	}
	for _, c := range checks {
		if s, ok := rc.find(c.kind, c.name, nil); !ok || s.value != c.want {
			t.Errorf("%s %s = %+v (ok=%v), want %v", c.kind, c.name, s, ok, c.want)
		}
	}
}

type fullRec struct {
	rec
	logs  []string
	attrs []map[string]string
	hist  map[string][]uint64
}

func (f *fullRec) Log(sev, body string, a map[string]string, _ time.Time) {
	f.logs = append(f.logs, sev+"|"+body)
	f.attrs = append(f.attrs, a)
}

func (f *fullRec) Histogram(name, _ string, _ []float64, counts []uint64, _ float64, _ uint64, _ map[string]string, _ time.Time) {
	if f.hist == nil {
		f.hist = map[string][]uint64{}
	}
	f.hist[name] = counts
}

func TestDogStatsDEventAndServiceCheck(t *testing.T) {
	d := NewDogStatsD()
	d.Feed("_e{5,11}:Alert|line1\\nl2 x|d:1700000000|h:web1|t:error|k:agg|#env:prod\n" +
		"_sc|db.up|2|h:web1|#env:prod|m:down | really\n_e{9,1}:short|x\n_sc|x|9")
	f := &fullRec{}
	d.Flush(f, time.Now())
	if len(f.logs) != 1 || f.logs[0] != "error|Alert\nline1\nl2 x" || f.attrs[0]["datadog.event"] != "true" ||
		f.attrs[0]["host.name"] != "web1" || f.attrs[0]["env"] != "prod" {
		t.Fatalf("event = %q %v", f.logs, f.attrs)
	}
	c, ok2 := f.find("gauge", "datadog.check_run.status", map[string]string{"check": "db.up", "message": "down | really", "host.name": "web1"})
	if !ok2 || c.value != 2 {
		t.Fatalf("check = %+v ok=%v", c, ok2)
	}
	if v, _ := f.find("sum", "wt_dogstatsd_invalid_total", nil); v.value != 2 {
		t.Fatalf("invalid = %v", v.value)
	}
}

func TestDogStatsDMapper(t *testing.T) {
	d := NewDogStatsD()
	d.maps = compileDogMaps([]DogMapping{{Match: "svc.*.req.*", Name: "svc.requests", Labels: map[string]string{"svc": "$1", "code": "$2"}}})
	d.Feed("svc.api.req.200:3|c\nsvc.api.other:1|c\nsvc.api.req.200.x:1|c")
	rc := &rec{}
	d.Flush(rc, time.Now())
	if s, ok := rc.find("sum", "svc.requests", map[string]string{"svc": "api", "code": "200"}); !ok || s.value != 3 {
		t.Fatalf("mapped = %+v ok=%v %+v", s, ok, rc.s)
	}
	if _, ok := rc.find("sum", "svc.api.other", nil); !ok {
		t.Fatal("unmatched name must pass through")
	}
}

func TestDogStatsDDistributionHistogramMerges(t *testing.T) {
	var vals []string
	for i := 1; i <= 100; i++ {
		vals = append(vals, itoa(i))
	}
	d := NewDogStatsD()
	d.Feed("lat:" + strings.Join(vals, ":") + "|d|#a:1")
	f := &fullRec{}
	d.Flush(f, time.Now())
	h := f.hist["lat"]
	if len(h) != len(dogBounds)+1 {
		t.Fatalf("buckets = %d", len(h))
	}
	var n uint64
	for _, c := range h {
		n += c
	}
	if n != 100 {
		t.Fatalf("count = %d", n)
	}
	// without a histogram exporter the summary is kept
	d.Feed("lat:5|d|#a:1")
	rc := &rec{}
	d.Flush(rc, time.Now())
	if _, ok := rc.find("gauge", "lat.avg", nil); !ok {
		t.Fatalf("fallback summary missing: %+v", rc.s)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
