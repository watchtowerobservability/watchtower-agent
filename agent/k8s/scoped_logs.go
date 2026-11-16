package k8s

import (
	"bufio"
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/watchtowerobservability/watchtower-agent/agent/logs"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	defaultLogStreams = 50
	logRetry          = 5 * time.Second
	logReconcile      = 5 * time.Second
	maxLogLine        = 1 << 20
)

// logStreamer follows container logs through the pods/log API (no hostPath), one stream per
// container of the pods in scope, at most max at once. Streams that end are reopened with
// sinceTime at the last line seen; a terminated container is read once to its end.
type logStreamer struct {
	cs    kubernetes.Interface
	s     *scoped
	max   int
	start time.Time

	mu     sync.Mutex
	active map[string]bool
	last   map[string]time.Time // per stream key: timestamp of the last line emitted
	done   map[string]bool      // terminated container instances read to the end
	retry  map[string]time.Time
	capped bool
}

func newLogStreamer(cs kubernetes.Interface, s *scoped, maxStreams int, start time.Time) *logStreamer {
	if maxStreams <= 0 {
		maxStreams = defaultLogStreams
	}
	return &logStreamer{cs: cs, s: s, max: maxStreams, start: start, active: map[string]bool{},
		last: map[string]time.Time{}, done: map[string]bool{}, retry: map[string]time.Time{}}
}

type logTarget struct {
	key, ns, pod, ctr string
	p                 *corev1.Pod
	finished          bool // terminated: read to the end, then stop for this instance
	doneKey           string
}

// wantedLogs lists the containers that have started (running or terminated).
func wantedLogs(pods []*corev1.Pod) []logTarget {
	var out []logTarget
	for _, p := range pods {
		all := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		for _, cs := range all {
			t := logTarget{key: string(p.UID) + "/" + cs.Name, ns: p.Namespace, pod: p.Name, ctr: cs.Name, p: p}
			switch {
			case cs.State.Running != nil:
			case cs.State.Terminated != nil:
				t.finished, t.doneKey = true, t.key+"/"+cs.State.Terminated.StartedAt.String()
			default:
				continue
			}
			out = append(out, t)
		}
	}
	return out
}

func (l *logStreamer) run(ctx context.Context) {
	t := time.NewTicker(logReconcile)
	defer t.Stop()
	for {
		l.reconcile(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (l *logStreamer) reconcile(ctx context.Context, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	skipped := 0
	for _, t := range wantedLogs(l.s.podList()) {
		if l.active[t.key] || (t.finished && l.done[t.doneKey]) || now.Before(l.retry[t.key]) {
			continue
		}
		if len(l.active) >= l.max {
			skipped++
			continue
		}
		l.active[t.key] = true
		go l.follow(ctx, t)
	}
	if skipped > 0 && !l.capped {
		slog.Warn("kubernetes: log stream cap reached; some containers are not followed (raise kubernetes.max_log_streams or narrow the selector)", "max", l.max)
	}
	l.capped = skipped > 0
}

func (l *logStreamer) follow(ctx context.Context, t logTarget) {
	l.mu.Lock()
	since := l.last[t.key]
	l.mu.Unlock()
	if since.IsZero() {
		since = l.start
	}
	err := l.stream(ctx, t, since)
	l.mu.Lock()
	delete(l.active, t.key)
	l.retry[t.key] = time.Now().Add(logRetry)
	if err == nil && t.finished {
		l.done[t.doneKey] = true
	}
	l.mu.Unlock()
}

func (l *logStreamer) stream(ctx context.Context, t logTarget, since time.Time) error {
	l.mu.Lock()
	resume := l.last[t.key]
	l.mu.Unlock()
	st := metav1.NewTime(since)
	rc, err := l.cs.CoreV1().Pods(t.ns).GetLogs(t.pod, &corev1.PodLogOptions{
		Container: t.ctr, Follow: true, Timestamps: true, SinceTime: &st}).Stream(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Debug("kubernetes: pod log stream", "pod", t.ns+"/"+t.pod, "container", t.ctr, "error", err)
		}
		return err
	}
	defer rc.Close()
	res := sink.With(PodAttrs(ctx, l.s.cfg.ClusterName, t.p, l.s.cl.lookup), "k8s.container.name", t.ctr)
	res["host.name"] = t.p.Spec.NodeName
	attrs := sink.Res(res)
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 64<<10), maxLogLine)
	for sc.Scan() {
		at, text := splitLogTime(sc.Text())
		// shortcut: sinceTime is inclusive, so the resumed stream repeats the last line; lines that
		// share its exact timestamp are dropped with it. Fine for ns-resolution stamps.
		if !resume.IsZero() && !at.After(resume) {
			continue
		}
		if !at.IsZero() {
			l.mu.Lock()
			l.last[t.key] = at
			l.mu.Unlock()
		}
		if at.IsZero() {
			at = time.Now()
		}
		l.s.out.Log(logs.Severity(text), text, attrs, at)
	}
	return sc.Err()
}

// splitLogTime splits "<RFC3339Nano> text" (PodLogOptions.Timestamps).
func splitLogTime(line string) (time.Time, string) {
	ts, text, ok := strings.Cut(line, " ")
	if !ok {
		return time.Time{}, line
	}
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, line
	}
	return at, text
}
