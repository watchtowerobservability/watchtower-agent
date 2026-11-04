package integrations

import (
	"sort"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Lag in time: every round records each partition's end offset with the time it was read. The
// time a group's committed offset was the end offset, found by interpolating that history (or,
// for a commit older than the history, extrapolating at the history's produce rate), is when the
// next unconsumed record was written; now minus that is how far behind the group is in seconds.
// No records are fetched. A partition whose producer is idle reports 0 once the group catches up.

const (
	maxEndHistory     = 60   // samples per partition (30 minutes at the default interval)
	maxTrackedEndsTPs = 5000 // partitions with a history; beyond it lag_time is counted as dropped
)

type endSample struct{ off, ms int64 }

type tp struct {
	topic     string
	partition int32
}

// record adds this round's end offsets and forgets partitions that no group consumes any more.
func (s *KafkaState) record(lags kadm.DescribedGroupLags, now time.Time) {
	if s.ends == nil {
		s.ends = map[tp][]endSample{}
	}
	ms := now.UnixMilli()
	seen := map[tp]bool{}
	for _, g := range lags {
		for _, ps := range g.Lag {
			for _, l := range ps {
				k := tp{l.Topic, l.Partition}
				if seen[k] || l.End.Err != nil || l.End.Offset < 0 {
					continue
				}
				seen[k] = true
				h, ok := s.ends[k]
				if !ok && len(s.ends) >= maxTrackedEndsTPs {
					s.drop(droppedSeries, 1)
					continue
				}
				if n := len(h); n > 0 && h[n-1].ms >= ms {
					continue // one sample per round
				}
				h = append(h, endSample{l.End.Offset, ms})
				if len(h) > maxEndHistory {
					h = append(h[:0], h[len(h)-maxEndHistory:]...)
				}
				s.ends[k] = h
			}
		}
	}
	for k := range s.ends {
		if !seen[k] {
			delete(s.ends, k)
		}
	}
}

// writtenAt estimates when the partition's end offset was commit (unix ms), from history h.
func writtenAt(h []endSample, commit int64) (int64, bool) {
	if len(h) == 0 {
		return 0, false
	}
	if commit >= h[len(h)-1].off {
		return h[len(h)-1].ms, true
	}
	if len(h) < 2 {
		return 0, false // one sample cannot date an older offset
	}
	i := sort.Search(len(h), func(i int) bool { return h[i].off > commit })
	if i > 0 { // h[i-1].off <= commit < h[i].off
		a, b := h[i-1], h[i]
		return a.ms + (commit-a.off)*(b.ms-a.ms)/(b.off-a.off), true
	}
	first, last := h[0], h[len(h)-1]
	if last.off <= first.off || last.ms <= first.ms {
		return first.ms, true // no produce rate known: at least as old as the history
	}
	back := float64(first.off-commit) * float64(last.ms-first.ms) / float64(last.off-first.off)
	return first.ms - int64(back), true
}

// emitLagTime writes kafka.consumer_group.lag_time: per group and topic, the largest lag in
// seconds over its partitions (the same group and topic pairs as lag_sum, at most maxLagSumSeries).
func emitLagTime(out sink.Sink, lags kadm.DescribedGroupLags, st *KafkaState, now time.Time) {
	st.record(lags, now)
	var pts []lagPoint
	for _, g := range lags.Sorted() {
		if g.Error() != nil {
			continue
		}
		for topic, ps := range g.Lag {
			worst, ok := 0.0, false
			for p, l := range ps {
				if l.Err != nil || l.Commit.At < 0 {
					continue
				}
				if l.Lag == 0 {
					ok = true
					continue
				}
				if at, found := writtenAt(st.ends[tp{topic, p}], l.Commit.At); found {
					worst, ok = max(worst, float64(now.UnixMilli()-at)/1000), true
				}
			}
			if ok {
				pts = append(pts, lagPoint{group: g.Group, topic: topic, lag: max(worst, 0)})
			}
		}
	}
	sortLag(pts)
	if len(pts) > maxLagSumSeries {
		pts = pts[:maxLagSumSeries]
	}
	for _, p := range pts {
		out.Gauge("kafka.consumer_group.lag_time", "s", p.lag, map[string]string{"group": p.group, "topic": p.topic}, now)
	}
}
