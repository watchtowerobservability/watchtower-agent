package cluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Heartbeat is how often a member refreshes its row; a member is live for 15 s after its last beat.
const Heartbeat = 5 * time.Second

// Member is one live replica.
type Member struct {
	ReplicaID, Role, Zone string
}

// Handle keeps this replica registered until Close.
type Handle struct {
	pool      *pgxpool.Pool
	replicaID string
	cancel    context.CancelFunc
	done      chan struct{}
}

func beat(ctx context.Context, p *pgxpool.Pool, id, role, zone string) error {
	_, err := p.Exec(ctx, `INSERT INTO cluster_members (replica_id, role, zone) VALUES ($1,$2,$3)
		ON CONFLICT (replica_id) DO UPDATE SET heartbeat_at = now(), role = $2, zone = $3`, id, role, zone)
	return err
}

// Join registers the replica (first heartbeat is synchronous) and heartbeats until Close.
func Join(ctx context.Context, pool *pgxpool.Pool, role, zone string) (*Handle, error) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	id := role + "-" + hex.EncodeToString(b[:])
	if err := beat(ctx, pool, id, role, zone); err != nil {
		return nil, err
	}
	bg, cancel := context.WithCancel(context.Background())
	h := &Handle{pool: pool, replicaID: id, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		t := time.NewTicker(Heartbeat)
		defer t.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-t.C:
				_ = beat(bg, pool, id, role, zone) // retried next tick; liveness lapses meanwhile
			}
		}
	}()
	return h, nil
}

// ReplicaID is this replica's id in cluster_members.
func (h *Handle) ReplicaID() string { return h.replicaID }

// Live lists members of role whose heartbeat is newer than 15 s.
func (h *Handle) Live(ctx context.Context, role string) ([]Member, error) {
	rows, err := h.pool.Query(ctx, `SELECT replica_id, role, zone FROM cluster_members
		WHERE role = $1 AND heartbeat_at > now() - interval '15 seconds' ORDER BY started_at, replica_id`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.ReplicaID, &m.Role, &m.Zone); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Close stops heartbeating and deregisters.
func (h *Handle) Close(ctx context.Context) error {
	h.cancel()
	<-h.done
	_, err := h.pool.Exec(ctx, `DELETE FROM cluster_members WHERE replica_id = $1`, h.replicaID)
	return err
}
