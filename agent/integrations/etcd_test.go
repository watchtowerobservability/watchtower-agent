package integrations

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// etcdMetrics renders a trimmed etcd 3.5 /metrics page with fsyncs observed so far.
func etcdMetrics(fast, slow int) string {
	return "# TYPE etcd_server_has_leader gauge\netcd_server_has_leader 1\n" +
		"# TYPE etcd_mvcc_db_total_size_in_bytes gauge\netcd_mvcc_db_total_size_in_bytes 1e9\n" +
		"# TYPE etcd_mvcc_db_total_size_in_use_in_bytes gauge\netcd_mvcc_db_total_size_in_use_in_bytes 3e8\n" +
		"# TYPE etcd_server_quota_backend_bytes gauge\netcd_server_quota_backend_bytes 2e9\n" +
		"# TYPE etcd_disk_wal_fsync_duration_seconds histogram\n" +
		"etcd_disk_wal_fsync_duration_seconds_bucket{le=\"0.001\"} " + strconv.Itoa(fast) + "\n" +
		"etcd_disk_wal_fsync_duration_seconds_bucket{le=\"0.008\"} " + strconv.Itoa(fast) + "\n" +
		"etcd_disk_wal_fsync_duration_seconds_bucket{le=\"0.128\"} " + strconv.Itoa(fast+slow) + "\n" +
		"etcd_disk_wal_fsync_duration_seconds_bucket{le=\"+Inf\"} " + strconv.Itoa(fast+slow) + "\n" +
		"etcd_disk_wal_fsync_duration_seconds_sum 1\netcd_disk_wal_fsync_duration_seconds_count " + strconv.Itoa(fast+slow) + "\n"
}

func TestEtcdDerived(t *testing.T) {
	tp := expfmt.NewTextParser(model.UTF8Validation)
	first, err := tp.TextToMetricFamilies(strings.NewReader(etcdMetrics(1000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	tp = expfmt.NewTextParser(model.UTF8Validation)
	second, err := tp.TextToMetricFamilies(strings.NewReader(etcdMetrics(1900, 100)))
	if err != nil {
		t.Fatal(err)
	}
	prev := map[string][]*dto.Bucket{}
	rec := &sink.Recorder{}
	EmitEtcdDerived(rec, first, prev, time.Now())
	if rec.Names()["etcd.disk.wal_fsync.p99"] {
		t.Fatal("no p99 before a second scrape")
	}
	EmitEtcdDerived(rec, second, prev, time.Now())
	// 900 fast and 100 slow fsyncs in the interval: p99 falls in the (0.008, 0.128] bucket.
	p99, _ := value(rec, "etcd.disk.wal_fsync.p99")
	if p99 <= 0.008 || p99 > 0.128 {
		t.Fatalf("p99 %v", p99)
	}
	if f, _ := value(rec, "etcd.db.fragmentation"); math.Abs(f-0.7) > 1e-9 {
		t.Fatalf("fragmentation %v", f)
	}
	if v, _ := value(rec, "etcd.db.defrag_recommended"); v != 1 {
		t.Fatal("700 MB reclaimable at 70% fragmentation must recommend a defrag")
	}
	if v, _ := value(rec, "etcd.db.quota_used"); v != 0.5 {
		t.Fatal(v)
	}
}
