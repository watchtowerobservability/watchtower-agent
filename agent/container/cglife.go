package container

import (
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// cgLife is the socket-free container lifecycle: a scope dir appearing is a start, vanishing a
// die, one that vanished and comes back (same id, or the same name once learned) a restart.
type cgLife struct {
	started bool
	live    map[string]cgLive // by container id
	gone    map[string]bool   // keys (name, else id) that vanished
	restart map[string]float64
	oom     map[string]uint64
}

type cgLive struct {
	key   string
	attrs map[string]string
}

const maxGone = 1000

func (p *Poller) lifeState() *cgLife {
	if p.life == nil {
		p.life = &cgLife{live: map[string]cgLive{}, gone: map[string]bool{}, restart: map[string]float64{}, oom: map[string]uint64{}}
	}
	return p.life
}

// lifeEach records one present container. The first scan only sets the baseline (no events).
func (p *Poller) lifeEach(out sink.Sink, c CG, name string, learnedName bool, attrs map[string]string, now time.Time) {
	l := p.lifeState()
	key := c.ID
	if learnedName {
		key = name
	}
	if _, was := l.live[c.ID]; !was && l.started {
		out.Log("INFO", "container start", sink.With(attrs, "container.event", "start"), now)
		if l.gone[key] {
			l.restart[key]++
			delete(l.gone, key)
		}
	}
	l.live[c.ID] = cgLive{key: key, attrs: attrs}
	out.Sum("container.restarts", "{restart}", l.restart[key], attrs, now)
	out.Sum("container.oom_kills", "{kill}", float64(c.OOMKills), attrs, now)
	if before, ok := l.oom[c.ID]; ok && c.OOMKills > before {
		out.Log("WARN", "container oom", sink.With(attrs, "container.event", "oom"), now)
	}
	l.oom[c.ID] = c.OOMKills
}

// lifeEnd emits die for ids that were present last scan and are not in seen.
func (p *Poller) lifeEnd(out sink.Sink, seen map[string]bool, now time.Time) {
	l := p.lifeState()
	for id, v := range l.live {
		if seen[id] {
			continue
		}
		out.Log("INFO", "container die", sink.With(v.attrs, "container.event", "die"), now)
		if len(l.gone) >= maxGone {
			l.gone = map[string]bool{}
		}
		l.gone[v.key] = true
		delete(l.live, id)
		delete(l.oom, id)
	}
	l.started = true
}
