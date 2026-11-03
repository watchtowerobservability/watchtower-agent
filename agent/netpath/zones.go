package netpath

import (
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Zone-to-zone connectivity (INF-019): every sample and record of a target is stamped with the
// zone the agent probes from and the zone of the destination, so the API can draw a matrix of
// wt_path_up by (path.src_zone, path.dst_zone). Without zones nothing is added.

type zoneSink struct {
	sink.Sink
	src string
	dst map[string]string // target name -> zone
}

func withZones(out sink.Sink, src string, ts []Target) sink.Sink {
	dst := map[string]string{}
	for _, t := range ts {
		if t.Zone != "" {
			dst[t.Name] = sink.Truncate(t.Zone, 128)
		}
	}
	if src == "" && len(dst) == 0 {
		return out
	}
	return zoneSink{out, sink.Truncate(src, 128), dst}
}

func (z zoneSink) stamp(a map[string]string) map[string]string {
	name, ok := a["path.target"]
	if !ok {
		return a
	}
	a = sink.With(a)
	if z.src != "" {
		a["path.src_zone"] = z.src
	}
	if d := z.dst[name]; d != "" {
		a["path.dst_zone"] = d
	}
	return a
}

func (z zoneSink) Gauge(n, u string, v float64, a map[string]string, at time.Time) {
	z.Sink.Gauge(n, u, v, z.stamp(a), at)
}

func (z zoneSink) Sum(n, u string, v float64, a map[string]string, at time.Time) {
	z.Sink.Sum(n, u, v, z.stamp(a), at)
}

func (z zoneSink) Log(sev, body string, a map[string]string, at time.Time) {
	z.Sink.Log(sev, body, z.stamp(a), at)
}
