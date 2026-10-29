package net

import (
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSMsg is the part of a DNS message the module keeps.
type DNSMsg struct {
	ID       uint16
	Response bool
	Name     string
	Type     string
	RCode    string
}

// ParseDNS parses a DNS payload header and first question.
func ParseDNS(b []byte) (DNSMsg, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		return DNSMsg{}, false
	}
	q, err := p.Question()
	if err != nil {
		return DNSMsg{}, false
	}
	return DNSMsg{
		ID: h.ID, Response: h.Response, Name: strings.TrimSuffix(q.Name.String(), "."),
		Type: strings.TrimPrefix(q.Type.String(), "Type"), RCode: strings.TrimPrefix(h.RCode.String(), "RCode"),
	}, true
}

type dnsKey struct {
	id   uint16
	port uint16 // client port
}

type dnsStat struct {
	n, lat, latN float64
}

// DNSTracker pairs queries with responses and counts them by (type, rcode).
type DNSTracker struct {
	pending map[dnsKey]time.Time
	stats   map[[2]string]*dnsStat
	fails   []string
}

// NewDNSTracker returns an empty tracker.
func NewDNSTracker() *DNSTracker {
	return &DNSTracker{pending: map[dnsKey]time.Time{}, stats: map[[2]string]*dnsStat{}}
}

// Observe records a packet at t; cport is the client's UDP port.
func (d *DNSTracker) Observe(m DNSMsg, cport uint16, t time.Time) {
	k := dnsKey{m.ID, cport}
	if !m.Response {
		if len(d.pending) > 4096 {
			clear(d.pending)
		}
		d.pending[k] = t
		return
	}
	s := d.stats[[2]string{m.Type, m.RCode}]
	if s == nil {
		s = &dnsStat{}
		d.stats[[2]string{m.Type, m.RCode}] = s
	}
	s.n++
	if q, ok := d.pending[k]; ok {
		delete(d.pending, k)
		s.lat += t.Sub(q).Seconds()
		s.latN++
	}
	if m.RCode != "Success" && len(d.fails) < maxFailLogs {
		d.fails = append(d.fails, m.Name+" "+m.RCode)
	}
}

// Flush exports cumulative counts, the mean latency of the interval, and failure events.
func (d *DNSTracker) Flush(out Exporter, at time.Time) {
	for k, s := range d.stats {
		a := map[string]string{"dns.question.type": k[0], "dns.response.code": k[1]}
		out.Sum("wt.net.dns.queries", "{query}", s.n, a, at)
		if s.latN > 0 {
			out.Gauge("wt.net.dns.latency", "s", s.lat/s.latN, a, at)
			s.lat, s.latN = 0, 0
		}
	}
	for _, f := range d.fails {
		out.Log("WARN", "dns query failed", map[string]string{"dns.failure": f}, at)
	}
	d.fails = d.fails[:0]
}
