package relay

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/watchtowerobservability/watchtower-agent/internal/wal"
)

// DefaultQueueBytes is relay.queue.max_bytes when unset (1 GiB).
const DefaultQueueBytes = 1 << 30

// ErrTooLarge is returned for a batch bigger than one WAL record (8 MiB).
var ErrTooLarge = errors.New("relay: batch exceeds the 8 MiB queue record limit")

// Queue is the relay's disk write-ahead log of processed OTLP batches. Records are
// `path NUL protobuf`. When the disk budget is full the oldest segments are dropped and every
// record in them is counted (Dropped), never silently.
type Queue struct {
	w *wal.WAL

	mu          sync.Mutex
	lastDropped int64
	depth       atomic.Int64
}

// OpenQueue opens (or creates) the queue in dir; records left by an earlier run are kept.
func OpenQueue(dir string, maxBytes int64) (*Queue, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultQueueBytes
	}
	w, err := wal.Open(dir, maxBytes)
	if err != nil {
		return nil, err
	}
	q := &Queue{w: w}
	q.depth.Store(w.Count())
	return q, nil
}

// Add appends one batch for path (`/v1/logs`, `/v1/traces`, `/v1/metrics`).
func (q *Queue) Add(path string, body []byte) error {
	rec := make([]byte, 0, len(path)+1+len(body))
	rec = append(append(append(rec, path...), 0), body...)
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.w.Append(rec); err != nil {
		if len(rec) > 8<<20 {
			return ErrTooLarge
		}
		return err
	}
	d := q.w.DroppedRecords()
	q.depth.Add(1 - (d - q.lastDropped))
	q.lastDropped = d
	return nil
}

// Depth is the number of queued batches. After a failed drain it can overcount by the part of a
// segment already delivered (those batches are sent again; the count is exact once drained).
func (q *Queue) Depth() int64 { return max(q.depth.Load(), 0) }

// Dropped is the number of batches discarded because the queue was full
// (`wt_relay_dropped_total`).
func (q *Queue) Dropped() int64 { return q.w.DroppedRecords() }

// Drain hands queued batches to fn oldest first. fn returning an error stops the drain; that
// batch and everything after it stay queued.
func (q *Queue) Drain(fn func(path string, body []byte) error) error {
	err := q.w.Replay(func(rec []byte) error {
		path, body, ok := bytes.Cut(rec, []byte{0})
		if !ok {
			return nil
		}
		if err := fn(string(path), body); err != nil {
			return err
		}
		q.depth.Add(-1)
		return nil
	})
	if err == nil {
		q.mu.Lock()
		q.depth.Store(q.w.Count())
		q.mu.Unlock()
	}
	return err
}

// Close closes the active segment.
func (q *Queue) Close() error { return q.w.Close() }
