package hw

import (
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Scope says what a device serves, so a hardware warning reaches the right workloads, SLOs and
// on-call team. It comes from the agent's own file and is stamped on every sample of the device
// as hw.* attributes (never wt.*: the gateway strips those from incoming data).
type Scope struct {
	Host      string   `json:"host"`        // the OS host that runs on this hardware
	Service   string   `json:"service"`     // service.name the host mainly serves
	SLO       string   `json:"slo"`         // SLO name that this hardware backs
	OnCall    string   `json:"oncall_team"` // team slug that is paged for it
	Workloads []string `json:"workloads"`   // workloads placed on it (at most 20)
}

const maxWorkloads = 20

// Attrs returns the scope as attributes (empty values are left out).
func (s Scope) Attrs() map[string]string {
	a := map[string]string{}
	for k, v := range map[string]string{
		"hw.host": s.Host, "hw.service": s.Service, "hw.slo": s.SLO, "hw.oncall_team": s.OnCall,
		"hw.workloads": strings.Join(s.Workloads[:min(len(s.Workloads), maxWorkloads)], ","),
	} {
		if v != "" {
			a[k] = sink.Truncate(v, 512)
		}
	}
	return a
}

// scoped adds a device's scope attributes to everything written through it.
type scoped struct {
	sink.Sink
	a map[string]string
}

func withScope(out sink.Sink, s Scope) sink.Sink {
	a := s.Attrs()
	if len(a) == 0 {
		return out
	}
	return scoped{out, a}
}

func merge(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func (s scoped) Gauge(n, u string, v float64, a map[string]string, at time.Time) {
	s.Sink.Gauge(n, u, v, merge(a, s.a), at)
}

func (s scoped) Sum(n, u string, v float64, a map[string]string, at time.Time) {
	s.Sink.Sum(n, u, v, merge(a, s.a), at)
}

func (s scoped) Log(sev, body string, a map[string]string, at time.Time) {
	s.Sink.Log(sev, body, merge(a, s.a), at)
}
