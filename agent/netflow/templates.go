package netflow

import (
	"container/list"
	"sync"
)

// Template cache bounds.
const (
	MaxTemplatesPerExporter = 1_000
	MaxTemplates            = 10_000
	MaxExporters            = 1_024
)

type tkey struct {
	exporter string
	domain   uint32
	id       uint16
	ipfix    bool
}

type field struct {
	typ uint16
	n   int
}

type template struct {
	fields []field
	recLen int
}

type entry struct {
	k      tkey
	t      *template
	global *list.Element
	local  *list.Element
}

type expState struct {
	ll    *list.List    // entries of this exporter, newest first
	order *list.Element // position in Templates.order
}

// Templates caches v9/IPFIX templates per exporter and observation domain, with LRU eviction at
// the per-exporter and the total bound. When more than MaxExporters exporters appear, the least
// recently seen exporter is evicted with all its templates (a spoofed source cannot lock a real
// exporter out); evictions are counted.
type Templates struct {
	mu      sync.Mutex
	m       map[tkey]*entry
	all     *list.List // newest first
	exps    map[string]*expState
	order   *list.List // exporter names, most recently seen first
	evicted uint64
}

// NewTemplates returns an empty cache.
func NewTemplates() *Templates {
	return &Templates{m: map[tkey]*entry{}, all: list.New(), exps: map[string]*expState{}, order: list.New()}
}

// Len is the number of cached templates.
func (c *Templates) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// Exporters is the number of exporters with cached templates.
func (c *Templates) Exporters() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.exps)
}

// Evicted counts the exporters dropped to stay within MaxExporters.
func (c *Templates) Evicted() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evicted
}

func (c *Templates) get(k tkey) *template {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[k]
	if e == nil {
		return nil
	}
	st := c.exps[k.exporter]
	c.all.MoveToFront(e.global)
	st.ll.MoveToFront(e.local)
	c.order.MoveToFront(st.order)
	return e.t
}

// drop removes e; the caller holds the lock.
func (c *Templates) drop(e *entry) {
	c.all.Remove(e.global)
	st := c.exps[e.k.exporter]
	st.ll.Remove(e.local)
	if st.ll.Len() == 0 {
		c.order.Remove(st.order)
		delete(c.exps, e.k.exporter)
	}
	delete(c.m, e.k)
}

func (c *Templates) delete(k tkey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.m[k]; e != nil {
		c.drop(e)
	}
}

func (c *Templates) put(k tkey, t *template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.m[k]; old != nil {
		c.drop(old)
	}
	if st := c.exps[k.exporter]; st != nil {
		for st.ll.Len() >= MaxTemplatesPerExporter {
			c.drop(st.ll.Back().Value.(*entry))
		}
	}
	for len(c.m) >= MaxTemplates {
		c.drop(c.all.Back().Value.(*entry))
	}
	for c.exps[k.exporter] == nil && len(c.exps) >= MaxExporters {
		name := c.order.Back().Value.(string)
		for c.exps[name] != nil { // dropping the last entry removes the exporter
			c.drop(c.exps[name].ll.Back().Value.(*entry))
		}
		c.evicted++
	}
	st := c.exps[k.exporter] // may have been emptied (and removed) by the evictions above
	if st == nil {
		st = &expState{ll: list.New()}
		st.order = c.order.PushFront(k.exporter)
		c.exps[k.exporter] = st
	} else {
		c.order.MoveToFront(st.order)
	}
	e := &entry{k: k, t: t}
	e.global, e.local = c.all.PushFront(e), st.ll.PushFront(e)
	c.m[k] = e
}
