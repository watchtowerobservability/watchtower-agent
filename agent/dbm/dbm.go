// Package dbm is database monitoring beyond counters (INF-027, APM-008, APM-024): bind-safe
// statement text, lock/wait chains and blocking sessions. The functions are pure; the engine
// modules in ../integrations feed them rows read through a read-only connection.
package dbm

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MaxChains bounds the chains reported per round.
const MaxChains = 20

// maxText bounds a reported statement.
const maxText = 500

// Session is one database session, as the engine's activity view reports it.
type Session struct {
	PID       int      `json:"pid"`
	BlockedBy []int    `json:"blocked_by,omitempty"`
	State     string   `json:"state,omitempty"`
	WaitEvent string   `json:"wait_event,omitempty"`
	Query     string   `json:"query,omitempty"`
	AgeMs     float64  `json:"age_ms,omitempty"`
	Locks     []string `json:"locks,omitempty"`
}

// Chain is one blocking tree: Root blocks everything in Waiters (transitively, nearest first).
type Chain struct {
	Root    Session   `json:"root"`
	Waiters []Session `json:"waiters"`
	Depth   int       `json:"depth"`
}

// BindSafe replaces every literal (quoted string, number, dollar-quoted body) with `?` so a
// sample never carries a bound value, then collapses whitespace and bounds the length.
func BindSafe(q string) string {
	var b strings.Builder
	rs := []rune(q)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\'':
			for i++; i < len(rs); i++ {
				if rs[i] == '\'' {
					if i+1 < len(rs) && rs[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			b.WriteByte('?')
		case c == '$' && i+1 < len(rs) && rs[i+1] == '$':
			j := i + 2
			for j+1 < len(rs) && (rs[j] != '$' || rs[j+1] != '$') {
				j++
			}
			b.WriteByte('?')
			i = min(j+1, len(rs))
		case c >= '0' && c <= '9' && (i == 0 || !isIdent(rs[i-1])):
			for i+1 < len(rs) && (rs[i+1] >= '0' && rs[i+1] <= '9' || rs[i+1] == '.') {
				i++
			}
			b.WriteByte('?')
		default:
			b.WriteRune(c)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > maxText {
		out = out[:maxText]
	}
	return out
}

func isIdent(r rune) bool {
	return r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// BuildChains turns sessions with their blockers into one chain per root blocker (a session
// that blocks others and is not itself blocked), longest first. A cycle (a deadlock the engine
// has not yet broken) has no root and is reported by its lowest pid with Depth counting the
// members. Chains are capped at MaxChains.
func BuildChains(sessions []Session) []Chain {
	by := map[int]Session{}
	kids := map[int][]int{}
	for _, s := range sessions {
		by[s.PID] = s
		for _, b := range s.BlockedBy {
			kids[b] = append(kids[b], s.PID)
		}
	}
	blocked := func(pid int) bool { return len(by[pid].BlockedBy) > 0 }
	var roots []int
	for pid := range kids {
		if !blocked(pid) {
			roots = append(roots, pid)
		}
	}
	sort.Ints(roots)
	var out []Chain
	seen := map[int]bool{}
	walk := func(root int) Chain {
		c := Chain{Root: by[root]}
		if _, ok := by[root]; !ok {
			c.Root = Session{PID: root}
		}
		level, depth := []int{root}, 0
		seen[root] = true
		for len(level) > 0 {
			var next []int
			for _, p := range level {
				for _, k := range kids[p] {
					if !seen[k] {
						seen[k] = true
						next = append(next, k)
						c.Waiters = append(c.Waiters, by[k])
					}
				}
			}
			if len(next) > 0 {
				depth++
			}
			level = next
		}
		c.Depth = depth
		return c
	}
	for _, r := range roots {
		out = append(out, walk(r))
	}
	// Cycles: every member is blocked, so no root was found for them.
	var rest []int
	for pid := range kids {
		if !seen[pid] {
			rest = append(rest, pid)
		}
	}
	sort.Ints(rest)
	for _, p := range rest {
		if !seen[p] {
			c := walk(p)
			c.Depth = len(c.Waiters) + 1
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Waiters) > len(out[j].Waiters) })
	if len(out) > MaxChains {
		out = out[:MaxChains]
	}
	return out
}

// Report emits the blocking gauges and one log record per chain. Statement text is bind-safe.
func Report(out sink.Sink, engine string, sessions []Session, now time.Time) {
	chains := BuildChains(sessions)
	blocked := 0
	for _, s := range sessions {
		if len(s.BlockedBy) > 0 {
			blocked++
		}
	}
	a := map[string]string{"db.system": engine}
	out.Gauge("db.sessions.blocked", "{sessions}", float64(blocked), a, now)
	longest := 0
	for _, c := range chains {
		longest = max(longest, c.Depth)
	}
	out.Gauge("db.blocking.chain_depth", "{sessions}", float64(longest), a, now)
	for _, c := range chains {
		c.Root.Query = BindSafe(c.Root.Query)
		for i := range c.Waiters {
			c.Waiters[i].Query = BindSafe(c.Waiters[i].Query)
		}
		body, err := json.Marshal(c)
		if err != nil {
			continue
		}
		out.Log("WARN", string(body), map[string]string{"db.system": engine, "wt.db.sample": "blocking_chain"}, now)
	}
}
