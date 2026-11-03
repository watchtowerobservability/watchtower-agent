package custom

import (
	"testing"
	"time"
)

func TestParseLocalChecksAndPiggyback(t *testing.T) {
	out := `<<<local:sep(0)>>>
0 "Disk queue" depth=3;10;20 Queue is fine
2 backup_age age=90000;86400;172800|size=12GB backup is old
P temp t=71;60;80 Temperature
P band v=5;10:20;0:30 below the band
3 nodata - cannot read
bogus line
<<<<db-replica-2>>>>
1 repl lag=12;10;60 Replication behind
<<<<>>>>
0 after - back to the agent host
`
	rs := ParseLocal(out)
	if len(rs) != 7 {
		t.Fatalf("got %d results: %+v", len(rs), rs)
	}
	want := []struct {
		svc  string
		st   Status
		host string
	}{
		{"Disk queue", OK, ""}, {"backup_age", Critical, ""}, {"temp", Warning, ""}, {"band", Warning, ""},
		{"nodata", Unknown, ""}, {"repl", Warning, "db-replica-2"}, {"after", OK, ""},
	}
	for i, w := range want {
		if rs[i].Service != w.svc || rs[i].Status != w.st || rs[i].Host != w.host {
			t.Errorf("%d: got %+v, want %+v", i, rs[i], w)
		}
	}
	if len(rs[1].Perf) != 2 || rs[1].Perf[1].UOM != "GB" || rs[0].Text != "Queue is fine" {
		t.Errorf("perf/text: %+v %+v", rs[1].Perf, rs[0])
	}
}

type resRecorder struct {
	plain, piggy []string
	host         string
}

func (r *resRecorder) Gauge(n, _ string, _ float64, _ map[string]string, _ time.Time) {
	r.plain = append(r.plain, n)
}
func (r *resRecorder) Sum(n, _ string, _ float64, _ map[string]string, _ time.Time) {}
func (r *resRecorder) GaugeRes(n, _ string, _ float64, res, _ map[string]string, _ time.Time) {
	r.piggy, r.host = append(r.piggy, n), res["host.name"]
}
func (r *resRecorder) SumRes(string, string, float64, map[string]string, map[string]string, time.Time) {
}

func TestPiggybackReportsAsTheOtherHost(t *testing.T) {
	var r resRecorder
	for _, res := range ParseLocal("<<<<web-7>>>>\n0 nginx conns=4 ok\n<<<<>>>>\n0 self - ok\n") {
		EmitLocal(&r, "check.sh", nil, res, time.Now())
	}
	if r.host != "web-7" || len(r.piggy) != 2 || len(r.plain) != 1 {
		t.Fatalf("plain %v piggy %v host %q", r.plain, r.piggy, r.host)
	}
}
