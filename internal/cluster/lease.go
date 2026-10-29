package cluster

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const checkEvery = 2 * time.Second

// Guard is a held leader lease: a session advisory lock on a connection it owns.
// The lock disappears with the connection, so a dead holder frees it.
type Guard struct {
	lost   atomic.Bool
	lostCh chan struct{}
	cancel context.CancelFunc
}

// Acquire returns (nil, nil) when another holder has the lease. ttl bounds one liveness check,
// so a lost connection is noticed within checkEvery+ttl.
func Acquire(ctx context.Context, pool *pgxpool.Pool, name string, ttl time.Duration) (*Guard, error) {
	pc, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn := pc.Hijack() // owned by the guard; closed when the lease ends
	var got bool
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, "wt-lease:"+name).Scan(&got)
	if err != nil || !got {
		_ = conn.Close(context.Background())
		return nil, err
	}
	bg, cancel := context.WithCancel(context.Background())
	g := &Guard{lostCh: make(chan struct{}), cancel: cancel}
	go g.watch(bg, conn, ttl)
	return g, nil
}

func (g *Guard) watch(ctx context.Context, conn *pgx.Conn, ttl time.Duration) {
	defer conn.Close(context.Background())
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, ttl)
			err := conn.Ping(c)
			cancel()
			if err != nil && ctx.Err() == nil {
				g.lost.Store(true)
				close(g.lostCh)
				return
			}
		}
	}
}

// IsValid is false once a liveness check has failed.
func (g *Guard) IsValid() bool { return !g.lost.Load() }

// Lost is closed when the lease is lost.
func (g *Guard) Lost() <-chan struct{} { return g.lostCh }

// Release gives the lease up.
func (g *Guard) Release() { g.cancel() }
