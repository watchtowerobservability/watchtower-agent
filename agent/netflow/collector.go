package netflow

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MaxPacket is the largest datagram read; a larger one is counted and dropped.
const MaxPacket = 9216

// Config is the module's own settings. An empty listen address means the default port, "off"
// disables that listener.
type Config struct {
	Enabled *bool  `json:"enabled"`
	NetFlow string `json:"netflow"` // default :2055 (v5, v9)
	IPFIX   string `json:"ipfix"`   // default :4739
	SFlow   string `json:"sflow"`   // default :6343
}

// Stats count what the collector saw.
type Stats struct {
	Packets, Flows, Malformed, NoTemplate, Oversize atomic.Uint64
}

// Collector decodes datagrams into the aggregator.
type Collector struct {
	Templates *Templates
	Agg       *Aggregator
	Stats     Stats
}

// New returns a collector with empty caches.
func New() *Collector { return &Collector{Templates: NewTemplates(), Agg: NewAggregator()} }

// Handle decodes one datagram from exporter. It never panics: whatever a packet does to a
// decoder, it ends up counted as malformed.
func (c *Collector) Handle(from netip.Addr, pkt []byte, now time.Time) {
	c.Stats.Packets.Add(1)
	defer func() {
		if recover() != nil {
			c.Stats.Malformed.Add(1)
		}
	}()
	if len(pkt) > MaxPacket {
		c.Stats.Oversize.Add(1)
		return
	}
	exp := from.Unmap().String()
	var (
		flows []Flow
		miss  int
		err   error
	)
	switch {
	case len(pkt) >= 4 && be32(pkt) == 5: // sFlow v5 (NetFlow v5 has 0x0005 in two bytes)
		flows, err = DecodeSFlow(pkt)
	case len(pkt) >= 2 && be16(pkt) == 5:
		flows, err = DecodeV5(pkt)
	case len(pkt) >= 2 && be16(pkt) == 9:
		flows, miss, err = c.Templates.DecodeV9(exp, pkt)
	case len(pkt) >= 2 && be16(pkt) == 10:
		flows, miss, err = c.Templates.DecodeIPFIX(exp, pkt)
	default:
		err = ErrMalformed
	}
	if err != nil {
		c.Stats.Malformed.Add(1)
	}
	c.Stats.NoTemplate.Add(uint64(miss))
	c.Stats.Flows.Add(uint64(len(flows)))
	for _, f := range flows {
		f.Exporter = exp
		c.Agg.Add(f, now)
	}
}

// Run listens until ctx ends. A listener that cannot bind is an error (the supervisor retries).
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var cfg Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return err
		}
	}
	if cfg.Enabled != nil && !*cfg.Enabled {
		<-ctx.Done()
		return nil
	}
	c := New()
	var conns []net.PacketConn
	defer func() {
		for _, pc := range conns {
			pc.Close()
		}
	}()
	for _, a := range []struct{ set, def string }{{cfg.NetFlow, ":2055"}, {cfg.IPFIX, ":4739"}, {cfg.SFlow, ":6343"}} {
		if a.set == "off" {
			continue
		}
		addr := a.set
		if addr == "" {
			addr = a.def
		}
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		conns = append(conns, pc)
	}
	var wg sync.WaitGroup
	for _, pc := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.read(pc)
		}()
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, pc := range conns {
				pc.Close()
			}
			wg.Wait()
			c.Agg.Flush(time.Now(), true, out)
			return nil
		case now := <-t.C:
			c.Agg.Flush(now, false, out)
			c.emitStats(out, now)
		}
	}
}

func (c *Collector) read(pc net.PacketConn) {
	buf := make([]byte, MaxPacket+1)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond) // a transient read error must not end the listener
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, _ := netip.AddrFromSlice(ua.IP)
		c.Handle(ip, buf[:n], time.Now())
	}
}

func (c *Collector) emitStats(out sink.Sink, at time.Time) {
	for name, v := range map[string]uint64{
		"packets": c.Stats.Packets.Load(), "flows": c.Stats.Flows.Load(),
		"malformed": c.Stats.Malformed.Load(), "no_template": c.Stats.NoTemplate.Load(),
		"oversize":          c.Stats.Oversize.Load(),
		"exporters_evicted": c.Templates.Evicted() + c.Agg.Evicted(),
	} {
		out.Sum("wt_flow_collector_"+name+"_total", "", float64(v), nil, at)
	}
}
