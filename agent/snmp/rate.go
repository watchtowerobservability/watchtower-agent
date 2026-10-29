package snmp

import (
	"strings"
	"sync"
	"time"
)

// Rates turns cumulative counters into per-second rates and keeps the other per-device state
// that lives across polls (sysUpTime, truncation counts).
//
// shortcut: series are never pruned; a device is capped at 10,000 varbinds per poll, so growth
// is bounded per device. Add expiry if interfaces churn a lot.
type Rates struct {
	mu      sync.Mutex
	prev    map[string]rateSample
	uptime  map[string]uint64
	trunc   map[string]float64
	lastLog map[string]time.Time
}

type rateSample struct {
	v  uint64
	at time.Time
}

// Update records v for the series key and returns the rate since the last call. bits is 32 or
// 64. A 32-bit counter that went down is taken to have wrapped once (emit checks the result
// against the interface speed and sysUpTime, which catch resets); a 64-bit one that went down
// was reset, so that interval yields no rate.
func (r *Rates) Update(key string, v uint64, bits int, at time.Time) (float64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prev == nil {
		r.prev = map[string]rateSample{}
	}
	p, seen := r.prev[key]
	r.prev[key] = rateSample{v, at}
	dt := at.Sub(p.at).Seconds()
	if !seen || dt <= 0 {
		return 0, false
	}
	delta := v - p.v
	if v < p.v {
		if bits != 32 {
			return 0, false
		}
		delta = v + (1 << 32) - p.v
	}
	return float64(delta) / dt, true
}

// WentBack records the device's sysUpTime (hundredths of a second) and reports whether it is
// lower than at the last poll: the device restarted, so every counter of it starts over.
func (r *Rates) WentBack(dev string, ticks uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.uptime == nil {
		r.uptime = map[string]uint64{}
	}
	last, seen := r.uptime[dev]
	r.uptime[dev] = ticks
	return seen && ticks < last
}

// Forget drops the counter baselines of one device, so its next samples only re-baseline.
func (r *Rates) Forget(dev string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.prev {
		if strings.HasPrefix(k, dev+"|") {
			delete(r.prev, k)
		}
	}
}

// Truncated counts one cut-off walk of dev's table and returns the running total and whether it
// should be logged now (once per device and table per hour).
func (r *Rates) Truncated(dev, table string, at time.Time) (float64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trunc == nil {
		r.trunc, r.lastLog = map[string]float64{}, map[string]time.Time{}
	}
	k := dev + "|" + table
	r.trunc[k]++
	if last, ok := r.lastLog[k]; ok && at.Sub(last) < time.Hour {
		return r.trunc[k], false
	}
	r.lastLog[k] = at
	return r.trunc[k], true
}
