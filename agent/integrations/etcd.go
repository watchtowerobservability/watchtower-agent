package integrations

// etcd depth (track A2): the member's /metrics (raft proposals, leader, disk, mvcc, peers)
// plus what the raw families do not say directly: interval p99 of WAL fsync, backend commit and
// peer round trip (from bucket deltas between rounds), database fragmentation, quota use and
// whether a defragmentation would pay off.

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

var etcdSpec = exporterSpec{name: "etcd", path: "/metrics", interval: 30 * time.Second,
	prefixes: []string{"etcd_server_", "etcd_mvcc_", "etcd_disk_", "etcd_network_", "etcd_debugging_mvcc_keys_total", "etcd_cluster_version"}}

// etcdHists are the histograms whose interval p99 is emitted (name -> metric).
var etcdHists = map[string]string{
	"etcd_disk_wal_fsync_duration_seconds":      "etcd.disk.wal_fsync.p99",
	"etcd_disk_backend_commit_duration_seconds": "etcd.disk.backend_commit.p99",
	"etcd_network_peer_round_trip_time_seconds": "etcd.network.peer_rtt.p99",
	"etcd_server_apply_duration_seconds":        "etcd.server.apply.p99",
	"etcd_disk_backend_defrag_duration_seconds": "etcd.disk.defrag.p99",
}

// Etcd scrapes a member (use the plain-HTTP --listen-metrics-urls port, 2381 by convention, when
// 2379 requires client certificates).
func Etcd(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &ExporterConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	if len(c.Prefixes) == 0 {
		c.Prefixes = etcdSpec.prefixes
	}
	target := c.URL
	if u, _ := url.Parse(c.URL); u.Path == "" || u.Path == "/" {
		target = strings.TrimRight(c.URL, "/") + etcdSpec.path
	}
	prev := map[string][]*dto.Bucket{}
	return Loop(ctx, "etcd", c.Base, etcdSpec.interval, out, func(ctx context.Context, now time.Time) error {
		fams, prefixes, err := scrapeFamilies(ctx, etcdSpec, c, target)
		if err != nil {
			return err
		}
		EmitFamilies(out, fams, prefixes, now)
		EmitEtcdDerived(out, fams, prev, now)
		return nil
	})
}

func famValue(fams map[string]*dto.MetricFamily, name string) (float64, bool) {
	f := fams[name]
	if f == nil || len(f.GetMetric()) == 0 {
		return 0, false
	}
	m := f.GetMetric()[0]
	switch f.GetType() {
	case dto.MetricType_COUNTER:
		return m.GetCounter().GetValue(), true
	case dto.MetricType_GAUGE:
		return m.GetGauge().GetValue(), true
	}
	return m.GetUntyped().GetValue(), true
}

// EmitEtcdDerived emits interval p99s (prev holds last round's buckets per series), fragmentation,
// quota use and the defrag hint.
func EmitEtcdDerived(out sink.Sink, fams map[string]*dto.MetricFamily, prev map[string][]*dto.Bucket, now time.Time) {
	for fam, name := range etcdHists {
		f := fams[fam]
		if f == nil {
			continue
		}
		for _, m := range f.GetMetric() {
			a := map[string]string{}
			var key strings.Builder
			key.WriteString(fam)
			for _, l := range m.GetLabel() {
				a[l.GetName()] = l.GetValue()
				key.WriteString("|" + l.GetName() + "=" + l.GetValue())
			}
			cur := m.GetHistogram().GetBucket()
			if p, ok := prev[key.String()]; ok {
				if q, ok := IntervalQuantile(p, cur, 0.99); ok {
					out.Gauge(name, "s", q, a, now)
				}
			}
			prev[key.String()] = cur
		}
	}
	total, ok1 := famValue(fams, "etcd_mvcc_db_total_size_in_bytes")
	inUse, ok2 := famValue(fams, "etcd_mvcc_db_total_size_in_use_in_bytes")
	if ok1 && ok2 && total > 0 {
		frag := 1 - inUse/total
		out.Gauge("etcd.db.fragmentation", "1", frag, nil, now)
		hint := 0.0
		if frag > 0.5 && total-inUse > 100<<20 { // half the file and 100 MiB reclaimable
			hint = 1
		}
		out.Gauge("etcd.db.defrag_recommended", "1", hint, nil, now)
	}
	if quota, ok := famValue(fams, "etcd_server_quota_backend_bytes"); ok && ok1 && quota > 0 {
		out.Gauge("etcd.db.quota_used", "1", total/quota, nil, now)
	}
}

// IntervalQuantile estimates quantile q of the observations made between two scrapes of one
// cumulative histogram (linear interpolation inside the bucket, as PromQL histogram_quantile).
// It reports false when nothing was observed or the counter reset.
func IntervalQuantile(prev, cur []*dto.Bucket, q float64) (float64, bool) {
	if len(prev) != len(cur) || len(cur) == 0 {
		return 0, false
	}
	type b struct{ le, n float64 }
	bs := make([]b, len(cur))
	for i := range cur {
		d := float64(cur[i].GetCumulativeCount()) - float64(prev[i].GetCumulativeCount())
		if d < 0 || cur[i].GetUpperBound() != prev[i].GetUpperBound() {
			return 0, false
		}
		bs[i] = b{cur[i].GetUpperBound(), d}
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].le < bs[j].le })
	total := bs[len(bs)-1].n
	if total <= 0 {
		return 0, false
	}
	rank := q * total
	lo, below := 0.0, 0.0
	for _, x := range bs {
		if x.n >= rank {
			if math.IsInf(x.le, 1) {
				return lo, true // past the last finite bound: report that bound
			}
			if x.n == below {
				return x.le, true
			}
			return lo + (x.le-lo)*(rank-below)/(x.n-below), true
		}
		lo, below = x.le, x.n
	}
	return lo, true
}
