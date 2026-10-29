package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// Timing of the Lease election. A crashed leader is replaced after at most LeaseDuration.
type Timing struct {
	LeaseDuration, RenewDeadline, RetryPeriod time.Duration
}

// DefaultTiming is client-go's usual 15 s / 10 s / 2 s.
var DefaultTiming = Timing{LeaseDuration: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second}

// RunElected competes for the Lease name in ns (coordination.k8s.io; RBAC: get and update on the
// pre-created lease) and calls lead only while this replica holds it; lead's context ends when
// leadership is lost or ctx ends. If lead returns an error while still leading, the Lease is
// released (the election context is cancelled, ReleaseOnCancel) and the replica waits one lease
// duration before competing again, so a standby can take over. After losing, the replica
// competes again until ctx ends. At most one replica
// runs lead at a time (up to one lease duration of overlap is possible after a network partition,
// which is why everything lead sends is at-least-once safe).
func RunElected(ctx context.Context, cs kubernetes.Interface, ns, name, id string, tm Timing, lead func(context.Context) error) error {
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: name, Namespace: ns},
		Client:     cs.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: id},
	}
	for ctx.Err() == nil {
		rctx, giveUp := context.WithCancel(ctx)
		failed := make(chan struct{})
		le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   tm.LeaseDuration,
			RenewDeadline:   tm.RenewDeadline,
			RetryPeriod:     tm.RetryPeriod,
			ReleaseOnCancel: true,
			Name:            name,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(c context.Context) {
					if err := lead(c); err != nil && c.Err() == nil {
						slog.Warn("k8s cluster agent cannot lead, releasing the lease", "error", err)
						close(failed)
						giveUp()
					}
				},
				OnStoppedLeading: func() { slog.Info("k8s cluster agent is no longer the leader", "id", id) },
				OnNewLeader: func(who string) {
					if who != id {
						slog.Info("k8s cluster agent leader is another replica", "leader", who)
					}
				},
			},
		})
		if err != nil {
			giveUp()
			return fmt.Errorf("leader election: %w", err)
		}
		le.Run(rctx) // returns when leadership is lost or the context ends (and releases the lease)
		giveUp()
		select {
		case <-failed:
			select {
			case <-ctx.Done():
			case <-time.After(tm.LeaseDuration):
			}
		default:
		}
	}
	return nil
}
