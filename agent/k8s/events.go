package k8s

import (
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	initialWindow = 5 * time.Minute // events older than this at start-up are history, not news
	seenCap       = 50_000
)

// limiter is a token bucket: perSec events per second with a burst of two seconds' worth.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
	dropped int
}

func newLimiter(perSec int) *limiter {
	r := float64(perSec)
	return &limiter{rate: r, burst: 2 * r, tokens: 2 * r}
}

func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		l.dropped++
		return false
	}
	l.tokens--
	return true
}

// takeDropped returns and resets the number of events dropped by the limiter.
func (l *limiter) takeDropped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.dropped
	l.dropped = 0
	return n
}

// eventSeen remembers the count last reported per event so a repeat is a new record only when
// its count grew. Bounded: cleared when it holds seenCap entries (a few duplicates follow).
type eventSeen struct {
	mu sync.Mutex
	m  map[types.UID]int32
}

func newEventSeen() *eventSeen { return &eventSeen{m: map[types.UID]int32{}} }

// fresh reports whether count is higher than what was reported for uid, and remembers it.
func (s *eventSeen) fresh(uid types.UID, count int32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.m[uid]; ok && old >= count {
		return false
	}
	if len(s.m) >= seenCap {
		s.m = map[types.UID]int32{}
	}
	s.m[uid] = count
	return true
}

func (s *eventSeen) has(uid types.UID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[uid]
	return ok
}

func (s *eventSeen) forget(uid types.UID) {
	s.mu.Lock()
	delete(s.m, uid)
	s.mu.Unlock()
}

func eventCount(e *corev1.Event) int32 {
	n := e.Count
	if e.Series != nil && e.Series.Count > n {
		n = e.Series.Count
	}
	return max(n, 1)
}

func eventTime(e *corev1.Event) time.Time {
	switch {
	case e.Series != nil && !e.Series.LastObservedTime.IsZero():
		return e.Series.LastObservedTime.Time
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}

func (c *cluster) eventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerDetailedFuncs{
		AddFunc: func(obj any, initial bool) {
			e, ok := obj.(*corev1.Event)
			if !ok {
				return
			}
			if initial && time.Since(eventTime(e)) > initialWindow {
				c.seen.fresh(e.UID, eventCount(e)) // known, not re-reported if it repeats
				return
			}
			c.logEvent(e)
		},
		UpdateFunc: func(_, obj any) {
			if e, ok := obj.(*corev1.Event); ok {
				c.logEvent(e)
			}
		},
		DeleteFunc: func(obj any) {
			if e, ok := obj.(*corev1.Event); ok {
				c.seen.forget(e.UID)
			}
		},
	}
}

// logEvent turns a Kubernetes Event into a log record: severity WARN for type Warning, the
// message as body, k8s.event.reason/type/count and k8s.event.object.{kind,name,namespace,uid}
// as attributes, cluster and namespace on the resource.
func (c *cluster) logEvent(e *corev1.Event) {
	n := eventCount(e)
	if !c.seen.fresh(e.UID, n) || !c.lim.allow(time.Now()) {
		return
	}
	res := map[string]string{}
	if c.cfg.ClusterName != "" {
		res["k8s.cluster.name"] = c.cfg.ClusterName
	}
	ns := e.InvolvedObject.Namespace
	if ns == "" {
		ns = e.Namespace
	}
	if ns != "" {
		res["k8s.namespace.name"] = ns
	}
	res["host.name"] = ""
	a := sink.Res(res)
	a["k8s.event.reason"] = e.Reason
	a["k8s.event.type"] = e.Type
	a["k8s.event.count"] = strconv.Itoa(int(n))
	a["k8s.event.object.kind"] = e.InvolvedObject.Kind
	a["k8s.event.object.name"] = e.InvolvedObject.Name
	a["k8s.event.object.namespace"] = e.InvolvedObject.Namespace
	a["k8s.event.object.uid"] = string(e.InvolvedObject.UID)
	sev := "INFO"
	if e.Type == corev1.EventTypeWarning {
		sev = "WARN"
	}
	at := eventTime(e)
	if at.IsZero() {
		at = time.Now()
	}
	c.out.Log(sev, sink.Truncate(e.Message, maxEventMessage), a, at)
}
