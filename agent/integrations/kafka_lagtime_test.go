package integrations

import (
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func groupLag(group string, commit, end int64) kadm.DescribedGroupLags {
	l := kadm.GroupMemberLag{Topic: "orders", Partition: 0, Commit: kadm.Offset{At: commit}, End: kadm.ListedOffset{Offset: end}, Lag: end - commit}
	return kadm.DescribedGroupLags{group: {Group: group, Lag: kadm.GroupLag{"orders": {0: l}}}}
}

func TestKafkaLagTimeInterpolatesEndOffsetHistory(t *testing.T) {
	st := &KafkaState{}
	t0 := time.Unix(1793620000, 0)
	// The producer writes 10 records a second; the group stops committing at offset 1000.
	for i := int64(0); i <= 10; i++ {
		now := t0.Add(time.Duration(i) * 30 * time.Second)
		r := &sink.Recorder{}
		emitLagTime(r, groupLag("billing", 1000, 1000+i*300), st, now)
		got, ok := value(r, "kafka.consumer_group.lag_time")
		if !ok {
			t.Fatalf("round %d: no lag_time", i)
		}
		if want := float64(i * 30); got != want {
			t.Fatalf("round %d: lag_time %v, want %v", i, got, want)
		}
	}
	// A commit inside the history interpolates: offset 2500 was the end 150 s after t0.
	r := &sink.Recorder{}
	now := t0.Add(330 * time.Second)
	emitLagTime(r, groupLag("billing", 2500, 1000+11*300), st, now)
	if got, _ := value(r, "kafka.consumer_group.lag_time"); got != 180 {
		t.Fatalf("interpolated lag_time %v, want 180", got)
	}
	if len(st.ends[tp{"orders", 0}]) != 12 {
		t.Fatalf("history %d samples", len(st.ends[tp{"orders", 0}]))
	}
}

func TestKafkaLagTimeExtrapolatesAndForgets(t *testing.T) {
	h := []endSample{{off: 1000, ms: 100_000}, {off: 2000, ms: 200_000}} // 10 records/s
	if at, ok := writtenAt(h, 500); !ok || at != 50_000 {
		t.Fatalf("extrapolated %v %v", at, ok)
	}
	if at, _ := writtenAt([]endSample{{1000, 100_000}, {1000, 200_000}}, 10); at != 100_000 {
		t.Fatalf("idle producer: at least as old as the history, got %v", at)
	}
	if _, ok := writtenAt(h[:1], 500); ok {
		t.Fatal("one sample cannot date an older commit")
	}
	st := &KafkaState{}
	r := &sink.Recorder{}
	emitLagTime(r, groupLag("caught-up", 500, 500), st, time.Unix(1, 0))
	if v, ok := value(r, "kafka.consumer_group.lag_time"); !ok || v != 0 {
		t.Fatalf("caught up: %v %v", v, ok)
	}
	emitLagTime(&sink.Recorder{}, kadm.DescribedGroupLags{}, st, time.Unix(31, 0))
	if len(st.ends) != 0 {
		t.Fatal("a partition no group consumes is forgotten")
	}
}
