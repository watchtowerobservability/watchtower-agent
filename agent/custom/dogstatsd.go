package custom

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	dogDefaultListen = "127.0.0.1:8125" // loopback by default; a pod or container listener sets ":8125"
	dogFlushEvery    = 10 * time.Second
	dogMaxSeries     = 10_000
	dogMaxDatagram   = 64 << 10
)

// DogStatsDConfig is the module config. It is local-file only (no Overlay): a listen address is
// a network exposure the server must not be able to open.
type DogStatsDConfig struct {
	Listen string `json:"listen"` // UDP address, default 127.0.0.1:8125
	Socket string `json:"socket"` // Unix datagram socket path, as well as or instead of Listen
	// Mappings rewrite dotted metric names into a name plus labels, first match wins. In Match,
	// `*` is one dot-separated segment; Name and Label values refer to the captures as $1, $2, ...
	Mappings []DogMapping `json:"mappings"`
}

// DogStatsD aggregates StatsD/DogStatsD datagrams into OTLP gauges and sums, flushed every 10 s:
//
//	g  gauge: the last value                    c  counter: cumulative sum of value/sample-rate
//	ms, h: <name>.count (cumulative, scaled by the sample rate), .avg, .min, .max, .95percentile
//	d  distribution: a cumulative histogram on fixed log-spaced bounds (mergeable across hosts and
//	   series); only an exporter without histograms gets the summary above instead
//	s  set: <name> is the number of distinct values in the interval
//
// Tags (`#k:v,flag`) become attributes. Events (`_e{..}:title|text|...`) become log records tagged
// `datadog.event` and service checks (`_sc|name|status|...`) the gauge `datadog.check_run.status`,
// the same shapes the gateway builds for the Datadog Agent API. Unparsable lines are counted in
// `wt_dogstatsd_invalid_total`.
type DogStatsD struct {
	mu      sync.Mutex
	series  map[string]*dogSeries
	ignored float64
	invalid float64
	dropped float64
	maps    []dogMap
	events  []dogEvent
	checks  []dogCheck
}

// logSink and histSink are the optional exporter capabilities events and distributions need.
type logSink interface {
	Log(severity, body string, attrs map[string]string, at time.Time)
}

type histSink interface {
	Histogram(name, unit string, bounds []float64, counts []uint64, sum float64, count uint64, attrs map[string]string, at time.Time)
}

// dogBounds are the shared histogram bounds, 2^(i/4) for i in [-20, 100]: ~19% wide buckets from
// 0.03 to 3e7. Every series uses the same bounds, so histograms merge by adding bucket counts.
var dogBounds = func() []float64 {
	b := make([]float64, 0, 121)
	for i := -20; i <= 100; i++ {
		b = append(b, math.Pow(2, float64(i)/4))
	}
	return b
}()

type dogSeries struct {
	name    string
	typ     string
	attrs   map[string]string
	gauge   float64
	counter float64 // cumulative
	count   float64 // cumulative, for timers and histograms
	vals    []float64
	hcounts []uint64 // distributions: per bucket, cumulative over the process life
	hsum    float64
	hcount  uint64
	set     map[string]struct{}
	dirty   bool
}

// NewDogStatsD returns an empty aggregator.
func NewDogStatsD() *DogStatsD { return &DogStatsD{series: map[string]*dogSeries{}} }

// Feed parses one datagram (any number of newline-separated lines).
func (d *DogStatsD) Feed(datagram string) {
	for _, ln := range strings.Split(datagram, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			d.line(ln)
		}
	}
}

func (d *DogStatsD) line(ln string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.HasPrefix(ln, "_e{") || strings.HasPrefix(ln, "_sc|") {
		if !d.special(ln) {
			d.invalid++
		}
		return
	}
	name, rest, ok := strings.Cut(ln, ":")
	if !ok || name == "" {
		d.invalid++
		return
	}
	parts := strings.Split(rest, "|")
	if len(parts) < 2 {
		d.invalid++
		return
	}
	typ, rate, tags := parts[1], 1.0, map[string]string{}
	for _, f := range parts[2:] {
		switch {
		case strings.HasPrefix(f, "@"):
			if r, err := strconv.ParseFloat(f[1:], 64); err == nil && r > 0 && r <= 1 {
				rate = r
			}
		case strings.HasPrefix(f, "#"):
			parseDogTags(f, tags)
		}
	}
	switch typ {
	case "g", "c", "ms", "h", "d", "s":
	default:
		d.invalid++
		return
	}
	name = d.remap(name, tags)
	attrs := sink.Strip(tags) // a tag must never name the OTLP resource
	key := name + "|" + typ + "|" + attrKey(attrs)
	s := d.series[key]
	if s == nil {
		if len(d.series) >= dogMaxSeries {
			d.dropped++
			return
		}
		s = &dogSeries{name: name, typ: typ, attrs: attrs}
		d.series[key] = s
	}
	// "name:1:2|ms" carries several values
	for _, v := range strings.Split(rest[:strings.IndexByte(rest, '|')], ":") {
		if !s.add(v, rate) {
			d.invalid++
		}
	}
}

func (s *dogSeries) add(raw string, rate float64) bool {
	if s.typ == "s" {
		if s.set == nil {
			s.set = map[string]struct{}{}
		}
		s.set[raw] = struct{}{}
		s.dirty = true
		return true
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return false
	}
	s.dirty = true
	switch s.typ {
	case "g":
		s.gauge = v
	case "c":
		s.counter += v / rate
	default:
		s.vals = append(s.vals, v)
		s.count += 1 / rate
		if s.typ == "d" {
			if s.hcounts == nil {
				s.hcounts = make([]uint64, len(dogBounds)+1)
			}
			n := uint64(math.Round(1 / rate))
			s.hcounts[sort.SearchFloat64s(dogBounds, v)] += n
			s.hsum += v * float64(n)
			s.hcount += n
		}
	}
	return true
}

func attrKey(a map[string]string) string {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + a[k] + ",")
	}
	return b.String()
}

// Flush writes what changed since the last flush. Gauges and counters are sent when touched;
// timer and histogram summaries and set sizes cover the interval and then reset.
func (d *DogStatsD) Flush(out Sink, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.series {
		if !s.dirty {
			continue
		}
		s.dirty = false
		switch s.typ {
		case "g":
			out.Gauge(s.name, "", s.gauge, s.attrs, now)
		case "c":
			out.Sum(s.name, "", s.counter, s.attrs, now)
		case "s":
			out.Gauge(s.name, "", float64(len(s.set)), s.attrs, now)
			s.set = nil
		default:
			if h, ok := out.(histSink); ok && s.typ == "d" {
				h.Histogram(s.name, "", dogBounds, append([]uint64(nil), s.hcounts...), s.hsum, s.hcount, s.attrs, now)
				s.vals = nil
				continue
			}
			sort.Float64s(s.vals)
			n, sum := len(s.vals), 0.0
			for _, v := range s.vals {
				sum += v
			}
			out.Sum(s.name+".count", "", s.count, s.attrs, now)
			out.Gauge(s.name+".avg", "", sum/float64(n), s.attrs, now)
			out.Gauge(s.name+".min", "", s.vals[0], s.attrs, now)
			out.Gauge(s.name+".max", "", s.vals[n-1], s.attrs, now)
			out.Gauge(s.name+".95percentile", "", s.vals[min(n-1, int(0.95*float64(n)))], s.attrs, now)
			s.vals = nil
		}
	}
	d.flushSpecial(out)
	out.Sum("wt_dogstatsd_ignored_total", "", d.ignored, nil, now)
	out.Sum("wt_dogstatsd_invalid_total", "", d.invalid, nil, now)
	out.Sum("wt_dogstatsd_dropped_series_total", "", d.dropped, nil, now)
}

// Run listens on UDP and/or a Unix datagram socket and flushes every 10 s until ctx ends.
func (*DogStatsD) Run(ctx context.Context, raw json.RawMessage, out Sink) error {
	var c DogStatsDConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if c.Listen == "" && c.Socket == "" {
		c.Listen = dogDefaultListen
	}
	d := NewDogStatsD()
	d.maps = compileDogMaps(c.Mappings)
	var conns []net.PacketConn
	if c.Listen != "" {
		pc, err := net.ListenPacket("udp", c.Listen)
		if err != nil {
			return err
		}
		conns = append(conns, pc)
	}
	if c.Socket != "" {
		_ = os.Remove(c.Socket) // a stale socket from a crash
		pc, err := net.ListenPacket("unixgram", c.Socket)
		if err != nil {
			for _, o := range conns {
				o.Close()
			}
			return err
		}
		_ = os.Chmod(c.Socket, 0o660)
		conns = append(conns, pc)
	}
	for _, pc := range conns {
		go func() {
			buf := make([]byte, dogMaxDatagram)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return // closed on shutdown
				}
				d.Feed(string(buf[:n]))
			}
		}()
	}
	t := time.NewTicker(dogFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, pc := range conns {
				pc.Close()
			}
			return nil
		case now := <-t.C:
			d.Flush(out, now)
		}
	}
}
