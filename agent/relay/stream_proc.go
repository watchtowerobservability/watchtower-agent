package relay

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// StreamProc configures one destination-side processor (`stream_processors:`). They run on
// events, after the edge-safe stages and before the destinations; the stream to the gateway is
// not affected.
//
//	dedupe: drop an event whose Fields (all fields but the timestamp when empty) were seen
//	        within Window; Max bounds the remembered entries (LRU).
//	quota:  at most MaxEvents / MaxBytes per Window for each value of Key (one global budget
//	        when empty). Excess events are dropped, or sent only to the Overflow destination.
type StreamProc struct {
	Type      string        `yaml:"type"`
	Name      string        `yaml:"name"` // metric label; default <type><index>
	Fields    []string      `yaml:"fields"`
	Key       string        `yaml:"key"`
	Window    time.Duration `yaml:"window"`
	Max       int           `yaml:"max_entries"` // dedupe entries or quota keys; default 100000 / 10000
	MaxEvents int64         `yaml:"max_events"`
	MaxBytes  int64         `yaml:"max_bytes"`
	Overflow  string        `yaml:"overflow"` // destination name; empty drops
}

// streamProc handles one batch; events it does not keep are counted, and overflow is added to
// over[destination].
type streamProc interface {
	apply(evs []Event, now time.Time, over map[string][]Event) []Event
	counts() (dropped, overflowed int64)
	label() string
}

func compileStream(i int, c StreamProc) (streamProc, error) {
	if c.Window <= 0 {
		c.Window = time.Minute
	}
	if c.Name == "" {
		c.Name = fmt.Sprintf("%s%d", c.Type, i)
	}
	switch c.Type {
	case "dedupe":
		if c.Max <= 0 {
			c.Max = 100000
		}
		return &dedupe{c: c, seen: map[[16]byte]*list.Element{}, lru: list.New()}, nil
	case "quota":
		if c.MaxEvents <= 0 && c.MaxBytes <= 0 {
			return nil, fmt.Errorf("stream_processors[%d]: quota needs max_events or max_bytes", i)
		}
		if c.Max <= 0 {
			c.Max = 10000
		}
		return &quota{c: c, keys: map[string]*bucket{}}, nil
	}
	return nil, fmt.Errorf("stream_processors[%d]: unknown type %q (dedupe or quota)", i, c.Type)
}

// field is a named event field, else an attribute of that name.
func field(e Event, f string) string {
	switch f {
	case "kind":
		return e.Kind
	case "name":
		return e.Name
	case "message":
		return e.Message
	case "severity":
		return e.Severity
	case "service":
		return e.Service
	case "trace_id":
		return e.TraceID
	case "span_id":
		return e.SpanID
	}
	return e.Attrs[f]
}

type dedupe struct {
	c       StreamProc
	mu      sync.Mutex
	seen    map[[16]byte]*list.Element // value: *dedupeEntry
	lru     *list.List                 // front = newest
	dropped atomic.Int64
}

type dedupeEntry struct {
	key   [16]byte
	first time.Time
}

func (d *dedupe) label() string          { return d.c.Name }
func (d *dedupe) counts() (int64, int64) { return d.dropped.Load(), 0 }

func (d *dedupe) key(e Event) [16]byte {
	h := sha256.New()
	if len(d.c.Fields) == 0 {
		e.Time = time.Time{}
		_ = json.NewEncoder(h).Encode(e) // map keys are sorted, so the encoding is stable
	} else {
		for _, f := range d.c.Fields {
			fmt.Fprintf(h, "%d:%s\x00", len(field(e, f)), field(e, f))
		}
	}
	var k [16]byte
	copy(k[:], h.Sum(nil))
	return k
}

func (d *dedupe) apply(evs []Event, now time.Time, _ map[string][]Event) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := evs[:0:0]
	for _, e := range evs {
		k := d.key(e)
		if el, ok := d.seen[k]; ok {
			ent := el.Value.(*dedupeEntry)
			if now.Sub(ent.first) < d.c.Window {
				d.dropped.Add(1)
				continue
			}
			ent.first = now // window passed: this one is new again
			d.lru.MoveToFront(el)
		} else {
			d.seen[k] = d.lru.PushFront(&dedupeEntry{k, now})
			for d.lru.Len() > d.c.Max { // shortcut: a flood of unique events can evict live entries early
				old := d.lru.Back()
				delete(d.seen, old.Value.(*dedupeEntry).key)
				d.lru.Remove(old)
			}
		}
		out = append(out, e)
	}
	return out
}

type bucket struct {
	start         time.Time
	events, bytes int64
}

type quota struct {
	c          StreamProc
	mu         sync.Mutex
	keys       map[string]*bucket
	dropped    atomic.Int64
	overflowed atomic.Int64
}

func (q *quota) label() string          { return q.c.Name }
func (q *quota) counts() (int64, int64) { return q.dropped.Load(), q.overflowed.Load() }

func (q *quota) apply(evs []Event, now time.Time, over map[string][]Event) []Event {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := evs[:0:0]
	for _, e := range evs {
		k := ""
		if q.c.Key != "" {
			k = field(e, q.c.Key)
		}
		b := q.bucket(k, now)
		var n int64
		if q.c.MaxBytes > 0 {
			j, _ := json.Marshal(e)
			n = int64(len(j))
		}
		if (q.c.MaxEvents > 0 && b.events+1 > q.c.MaxEvents) || (q.c.MaxBytes > 0 && b.bytes+n > q.c.MaxBytes) {
			if q.c.Overflow != "" {
				over[q.c.Overflow] = append(over[q.c.Overflow], e)
				q.overflowed.Add(1)
			} else {
				q.dropped.Add(1)
			}
			continue
		}
		b.events++
		b.bytes += n
		out = append(out, e)
	}
	return out
}

func (q *quota) bucket(k string, now time.Time) *bucket {
	b := q.keys[k]
	if b == nil {
		if len(q.keys) >= q.c.Max {
			for old, ob := range q.keys {
				if now.Sub(ob.start) >= q.c.Window {
					delete(q.keys, old)
				}
			}
			if len(q.keys) >= q.c.Max { // shortcut: keys past the bound share one budget, raise max_entries
				k = "\x00other"
				if b = q.keys[k]; b != nil {
					return q.roll(b, now)
				}
			}
		}
		b = &bucket{start: now}
		q.keys[k] = b
	}
	return q.roll(b, now)
}

func (q *quota) roll(b *bucket, now time.Time) *bucket {
	if now.Sub(b.start) >= q.c.Window {
		*b = bucket{start: now}
	}
	return b
}
