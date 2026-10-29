// Package wal is a small append-only disk queue: 16 MiB segments, a CRC32 per record, replay
// oldest first. Delivery from it is at-least-once: a crash between a successful send and the
// removal of its segment replays that segment's records again.
package wal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// DefaultMaxBytes is the cap on all segments together.
	DefaultMaxBytes = 512 << 20
	segmentBytes    = 16 << 20
	maxRecord       = 8 << 20
	segExt          = ".seg"
)

// ErrFull is returned by Append on a DropNewest queue that has reached MaxBytes.
var ErrFull = errors.New("wal: queue full")

// WAL is the queue. Use Open to create one.
type WAL struct {
	Dir      string
	MaxBytes int64 // default 512 MiB
	// DropNewest makes a full queue refuse new records (Append returns ErrFull) instead of
	// discarding the oldest segment (the default).
	DropNewest bool

	mu          sync.Mutex
	f           *os.File
	seq         uint64
	cur         int64
	dropped     atomic.Int64
	droppedRecs atomic.Int64
}

// Open creates dir and picks up the segments left by an earlier run.
func Open(dir string, maxBytes int64) (*WAL, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &WAL{Dir: dir, MaxBytes: maxBytes}
	segs, err := w.segments()
	if err != nil {
		return nil, err
	}
	if len(segs) > 0 {
		w.seq = segs[len(segs)-1]
	}
	return w, nil
}

// Dropped is the number of segments discarded because MaxBytes was exceeded.
func (w *WAL) Dropped() int64 { return w.dropped.Load() }

// DroppedRecords is the number of records inside the segments discarded because MaxBytes was
// exceeded.
func (w *WAL) DroppedRecords() int64 { return w.droppedRecs.Load() }

// Count is the number of intact records on disk, for a queue depth after a restart.
func (w *WAL) Count() int64 {
	segs, _ := w.segments()
	var n int64
	for _, s := range segs {
		n += w.countSegment(s)
	}
	return n
}

func (w *WAL) countSegment(seq uint64) int64 {
	var n int64
	_ = w.replaySegment(seq, func([]byte) error { n++; return nil })
	return n
}

func (w *WAL) name(seq uint64) string {
	return filepath.Join(w.Dir, fmt.Sprintf("%020d%s", seq, segExt))
}

// segments lists segment numbers, oldest first.
func (w *WAL) segments() ([]uint64, error) {
	ents, err := os.ReadDir(w.Dir)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range ents {
		if s, ok := strings.CutSuffix(e.Name(), segExt); ok {
			var n uint64
			if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
				out = append(out, n)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// Append writes one record (length, CRC32, payload) and syncs it.
func (w *WAL) Append(rec []byte) error {
	if len(rec) > maxRecord {
		return fmt.Errorf("wal: record of %d bytes exceeds %d", len(rec), maxRecord)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil || w.cur+int64(len(rec))+8 > segmentBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	hdr := make([]byte, 8, 8+len(rec))
	binary.LittleEndian.PutUint32(hdr[:4], uint32(len(rec)))
	binary.LittleEndian.PutUint32(hdr[4:], crc32.ChecksumIEEE(rec))
	if _, err := w.f.Write(append(hdr, rec...)); err != nil {
		return err
	}
	w.cur += int64(len(rec)) + 8
	return w.f.Sync()
}

// totalBytes is the size of all segments on disk.
func (w *WAL) totalBytes() int64 {
	segs, _ := w.segments()
	var n int64
	for _, s := range segs {
		if fi, err := os.Stat(w.name(s)); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// rotate starts a new segment and drops the oldest ones while the total is over MaxBytes.
func (w *WAL) rotate() error {
	if w.DropNewest {
		if t := w.totalBytes(); t > 0 && t+segmentBytes > w.MaxBytes {
			return ErrFull
		}
	}
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	w.seq++
	f, err := os.OpenFile(w.name(w.seq), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.f, w.cur = f, 0
	segs, err := w.segments()
	if err != nil {
		return err
	}
	var total int64
	sizes := map[uint64]int64{}
	for _, s := range segs {
		if fi, err := os.Stat(w.name(s)); err == nil {
			sizes[s] = fi.Size()
			total += fi.Size()
		}
	}
	// the new segment is always kept, even when MaxBytes is below one segment
	for _, s := range segs {
		if total+segmentBytes <= w.MaxBytes || s == w.seq {
			break
		}
		lost := w.countSegment(s)
		if os.Remove(w.name(s)) == nil {
			w.droppedRecs.Add(lost)
			total -= sizes[s]
			w.dropped.Add(1)
		}
	}
	return nil
}

// Replay hands every stored record to fn, oldest first. A segment is removed once all its
// records were accepted (fn returned nil); on an error from fn Replay stops and returns it, and
// that segment is replayed again next time. A torn or corrupt tail record ends its segment.
func (w *WAL) Replay(fn func(rec []byte) error) error {
	w.mu.Lock()
	if w.f != nil { // seal the active segment so new appends open a later one
		_ = w.f.Close()
		w.f = nil
	}
	w.mu.Unlock()
	segs, err := w.segments()
	if err != nil {
		return err
	}
	for _, s := range segs {
		if err := w.replaySegment(s, fn); err != nil {
			return err
		}
		if err := os.Remove(w.name(s)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (w *WAL) replaySegment(seq uint64, fn func([]byte) error) error {
	f, err := os.Open(w.name(seq))
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil // end of segment or torn header
		}
		n := binary.LittleEndian.Uint32(hdr[:4])
		if n > maxRecord {
			return nil
		}
		rec := make([]byte, n)
		if _, err := io.ReadFull(r, rec); err != nil {
			return nil // torn payload
		}
		if crc32.ChecksumIEEE(rec) != binary.LittleEndian.Uint32(hdr[4:]) {
			return nil
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}

// Close closes the active segment.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
