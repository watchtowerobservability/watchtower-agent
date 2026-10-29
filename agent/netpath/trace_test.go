package netpath

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// route answers a probe from a fixed list of router addresses; the last one is the destination.
type route struct {
	hops    []string
	viaPort map[uint16][]string // a different route for some source ports
}

func (r *route) Probe(_ context.Context, ttl int, src uint16) Result {
	h := r.hops
	if alt, ok := r.viaPort[src]; ok {
		h = alt
	}
	if ttl > len(h) || h[ttl-1] == "" {
		return Result{}
	}
	return Result{Addr: netip.MustParseAddr(h[ttl-1]), RTT: time.Millisecond, Reached: ttl == len(h)}
}

func TestTCPSynTraceroute(t *testing.T) {
	r := &route{hops: []string{"10.0.0.1", "", "192.0.2.9", "198.51.100.7"}}
	p := Trace(context.Background(), r, 30, 40000)
	if !p.Reached || len(p.Hops) != 4 || !p.Hops[1].Lost || p.Hops[3].Addr != "198.51.100.7" {
		t.Fatalf("path %+v", p)
	}
	if p.Signature() != "10.0.0.1>*>192.0.2.9>198.51.100.7" {
		t.Fatalf("signature %q", p.Signature())
	}
	if _, bad := Blame(p); bad {
		t.Fatal("a path that reached its destination blames no hop")
	}
	// the destination never answers: blame the last router that did
	dead := Trace(context.Background(), &route{hops: []string{"10.0.0.1", "192.0.2.9", "", "", ""}}, 30, 40000)
	cu, bad := Blame(dead)
	if !bad || cu.TTL != 2 || cu.Addr != "192.0.2.9" {
		t.Fatalf("blame %+v %v", cu, bad)
	}
	if len(dead.Hops) != 5 { // stops after 3 silent hops
		t.Fatalf("hops %d", len(dead.Hops))
	}
}

func TestMultipathAndPathChange(t *testing.T) {
	r := &route{hops: []string{"10.0.0.1", "192.0.2.1", "203.0.113.5"},
		viaPort: map[uint16][]string{40001: {"10.0.0.1", "192.0.2.2", "203.0.113.5"}}}
	paths := Multipath(context.Background(), r, 30, 4, 40000)
	if len(paths) != 2 {
		t.Fatalf("distinct routes %d", len(paths))
	}
	var d Detector
	if _, ch := d.Observe("db", paths); ch {
		t.Fatal("first observation is not a change")
	}
	if _, ch := d.Observe("db", paths); ch {
		t.Fatal("same routes are not a change")
	}
	r.hops = []string{"10.0.0.1", "192.0.2.77", "203.0.113.5"}
	if _, ch := d.Observe("db", Multipath(context.Background(), r, 30, 4, 40000)); !ch {
		t.Fatal("a new route must be reported")
	}
}

func TestSocketTargetEmitsChange(t *testing.T) {
	r := &route{hops: []string{"10.0.0.1", "203.0.113.5"}}
	old := newProber
	newProber = func(string, netip.AddrPort) Prober { return r }
	defer func() { newProber = old }()
	var rec sink.Recorder
	tg := Target{Name: "api", Host: "127.0.0.1", Proto: ProtoTCP}
	Once(context.Background(), fake, []Target{tg}, &rec, time.Now())
	r.hops = []string{"10.0.0.2", "203.0.113.5"}
	Once(context.Background(), fake, []Target{tg}, &rec, time.Now())
	n := 0
	for _, s := range rec.Samples {
		if s.Attrs["event.name"] == "network.path_change" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("path_change logs %d", n)
	}
}
