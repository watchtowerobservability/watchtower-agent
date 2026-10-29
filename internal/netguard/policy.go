package netguard

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Policy is the egress policy of one HTTP client (R28). With DenyAll, only AllowHosts may be
// dialled; otherwise any public host may (private ranges stay blocked unless AllowPrivate).
type Policy struct {
	// AllowHosts are exact host names, IP literals or "*.suffix" patterns (no ports).
	AllowHosts []string
	// AllowPrivate lets the client reach private address space.
	AllowPrivate bool
	// DenyAll refuses every host that is not in AllowHosts.
	DenyAll bool
	// Purpose names the caller for the denied counter; unknown values count as "other".
	Purpose string
}

// ErrEgressDenied is returned (wrapped) when the policy refuses a host.
type ErrEgressDenied struct{ Host, Purpose string }

func (e *ErrEgressDenied) Error() string {
	return fmt.Sprintf("egress to %q denied by policy (purpose %q)", e.Host, e.Purpose)
}

// FromEnv is the first-party policy: unrestricted (private ranges allowed, as in-cluster calls
// need) unless WT_AIRGAP=1, when every host except those in WT_EGRESS_ALLOW (comma separated) is
// denied.
func FromEnv(purpose string) Policy {
	p := Policy{AllowPrivate: true, Purpose: purpose}
	if os.Getenv("WT_AIRGAP") == "1" {
		p.DenyAll = true
		for _, h := range strings.Split(os.Getenv("WT_EGRESS_ALLOW"), ",") {
			if h = strings.TrimSpace(h); h != "" {
				p.AllowHosts = append(p.AllowHosts, h)
			}
		}
	}
	return p
}

// HostAllowed reports whether the policy lets host (no port) be dialled.
func (p Policy) HostAllowed(host string) bool {
	if !p.DenyAll {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range p.AllowHosts {
		a = strings.ToLower(a)
		if a == host || (strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:])) {
			return true
		}
	}
	return false
}

// maxPurposes bounds the label cardinality of wt_egress_denied_total: callers pass their own
// purpose strings and the first maxPurposes distinct ones are kept, the rest count as "other".
const maxPurposes = 32

var (
	deniedMu sync.Mutex
	denied   = map[string]uint64{}
)

func countDenied(purpose string) string {
	deniedMu.Lock()
	if _, seen := denied[purpose]; !seen && (len(denied) >= maxPurposes || len(purpose) > 32) {
		purpose = "other"
	}
	denied[purpose]++
	deniedMu.Unlock()
	return purpose
}

// DeniedTotal returns wt_egress_denied_total per purpose.
func DeniedTotal() map[string]uint64 {
	deniedMu.Lock()
	defer deniedMu.Unlock()
	out := make(map[string]uint64, len(denied))
	for k, v := range denied {
		out[k] = v
	}
	return out
}

// MetricsText renders wt_egress_denied_total in Prometheus text format for a /metrics handler.
func MetricsText() string {
	var b strings.Builder
	b.WriteString("# TYPE wt_egress_denied_total counter\n")
	for k, v := range DeniedTotal() {
		fmt.Fprintf(&b, "wt_egress_denied_total{purpose=%q} %d\n", k, v)
	}
	return b.String()
}
