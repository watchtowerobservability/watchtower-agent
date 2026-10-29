package k8s

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// A leader whose caches never sync retries, then gives up and releases the Lease so the standby
// (whose API works) takes over.
func TestLeaderReleasesLeaseWhenCachesNeverSync(t *testing.T) {
	oldSync, oldAttempts, oldBackoff := syncTimeout, leadAttempts, leadBackoff
	syncTimeout, leadAttempts, leadBackoff = 150*time.Millisecond, 2, 50*time.Millisecond
	t.Cleanup(func() { syncTimeout, leadAttempts, leadBackoff = oldSync, oldAttempts, oldBackoff })

	// Both replicas share the Lease on `leases`; replica A reads its data from `broken`, whose
	// pod list always fails, so its informers never sync.
	leases := fake.NewClientset()
	broken := fake.NewClientset()
	broken.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	healthy := fake.NewClientset(fixtureObjects()...)

	tm := Timing{LeaseDuration: 600 * time.Millisecond, RenewDeadline: 400 * time.Millisecond, RetryPeriod: 50 * time.Millisecond}
	var aFailed, bLed atomic.Int32
	recB := &sink.Recorder{}
	leadWith := func(data *fake.Clientset, out sink.Sink, led, failed *atomic.Int32) func(context.Context) error {
		return func(ctx context.Context) error {
			err := leadWithRetry(ctx, func(ctx context.Context) error {
				return runLeader(ctx, data, ClusterConfig{ClusterName: "prod", EventsPerSec: 10, Interval: "10s"}, out)
			})
			if err != nil {
				failed.Add(1)
			}
			if led != nil {
				led.Add(1)
			}
			return err
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// A is started first so it wins the Lease.
	go func() {
		_ = RunElected(ctx, leases, "wt", "wt-cluster-agent", "a", tm, leadWith(broken, &sink.Recorder{}, nil, &aFailed))
	}()
	eventually(t, "A gives up", func() bool { return aFailed.Load() == 1 })
	go func() {
		_ = RunElected(ctx, leases, "wt", "wt-cluster-agent", "b", tm, leadWith(healthy, recB, &bLed, &aFailed))
	}()
	eventually(t, "B takes over and reports", func() bool { return find(recB, "k8s.deployment.desired") != nil })
	if _, err := leases.CoordinationV1().Leases("wt").Get(ctx, "wt-cluster-agent", metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if bLed.Load() != 0 {
		t.Fatal("B must still be leading (its lead function has not returned)")
	}
}
