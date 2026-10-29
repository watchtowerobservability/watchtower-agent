package netpath

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

// Tracer runs one ICMP trace and returns the hops as JSON, the hop count and whether the
// destination answered. errText is empty on success.
type Tracer func(ctx context.Context, host string, maxHops, probes int) (body string, hops int, reached bool, errText string)

const (
	icmpMaxHops  = 30
	icmpProbes   = 3
	errRawICMP   = "network_path_needs_raw_icmp" // CAP_NET_RAW (or root) is required
	icmpProbeGap = time.Second
)

var probeSeq atomic.Uint32 // unique echo sequence numbers across concurrent traces

type icmpProbe struct {
	RTTMS float64 `json:"rtt_ms,omitempty"`
	Lost  bool    `json:"lost,omitempty"`
}

type icmpHop struct {
	TTL    int         `json:"ttl"`
	Addr   string      `json:"addr,omitempty"`
	Probes []icmpProbe `json:"probes"`
}

// validHost rejects hosts that are not a plain name or address.
func validHost(h string) error {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " \t\r\n/\\@?#") {
		return errors.New("host is not valid")
	}
	return nil
}

// ICMPTracer is the agent's own TTL-stepped ICMP traceroute; the agent may trace private space.
func ICMPTracer(ctx context.Context, host string, maxHops, probes int) (string, int, bool, string) {
	ip, err := resolve(ctx, host)
	if err != nil {
		return "", 0, false, err.Error()
	}
	hops, reached, err := icmpTrace(ctx, ip, maxHops, probes)
	body, _ := json.Marshal(hops)
	switch {
	case err != nil:
		return string(body), len(hops), false, err.Error()
	case reached:
		return string(body), len(hops), true, ""
	case ctx.Err() != nil: // out of time: the hops traced are the result, the path itself is up
		return string(body), len(hops), len(hops) > 0, ""
	}
	return string(body), len(hops), false, "the destination did not answer within the hop limit"
}

func resolve(ctx context.Context, host string) (netip.Addr, error) {
	var ip netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		ip = a.Unmap()
	} else {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return ip, errors.New("host not found")
		}
		ip = ips[0].Unmap()
	}
	if !ip.Is4() {
		return ip, errors.New("only IPv4 targets are supported")
	}
	if netguard.Blocked(ip, true) {
		return ip, errors.New("target blocked")
	}
	return ip, nil
}

func icmpTrace(ctx context.Context, dst netip.Addr, hopsMax, probes int) ([]icmpHop, bool, error) {
	hopsMax, probes = min(max(hopsMax, 1), icmpMaxHops), min(max(probes, 1), icmpProbes)
	raw, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, false, errors.New(errRawICMP)
	}
	defer raw.Close()
	pc := raw.IPv4PacketConn()
	var hops []icmpHop
	for ttl := 1; ttl <= hopsMax; ttl++ {
		hop := icmpHop{TTL: ttl}
		reached := false
		_ = pc.SetTTL(ttl)
		for range probes {
			if ctx.Err() != nil {
				return hops, false, nil
			}
			addr, rtt, done := probeOnce(ctx, raw, dst, 0x5754, int(probeSeq.Add(1)&0xffff))
			if !addr.IsValid() {
				hop.Probes = append(hop.Probes, icmpProbe{Lost: true}) // a silent hop costs one wait
				break
			}
			hop.Probes = append(hop.Probes, icmpProbe{RTTMS: float64(rtt) / float64(time.Millisecond)})
			hop.Addr = addr.String()
			reached = reached || done
		}
		hops = append(hops, hop)
		if reached {
			return hops, true, nil
		}
	}
	return hops, false, nil
}

func probeOnce(ctx context.Context, conn *icmp.PacketConn, dst netip.Addr, id, seq int) (netip.Addr, time.Duration, bool) {
	wire, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("watchtower")}}).Marshal(nil)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	start := time.Now()
	deadline := start.Add(icmpProbeGap)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.WriteTo(wire, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
		return netip.Addr{}, 0, false
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		gotID, gotSeq, reply, ok := matchProbe(buf[:n])
		if !ok || gotID != id || gotSeq != seq {
			continue
		}
		ip, _ := netip.AddrFromSlice(peer.(*net.IPAddr).IP)
		ip = ip.Unmap()
		return ip, time.Since(start), reply && ip == dst
	}
}

func matchProbe(b []byte) (id, seq int, reply, ok bool) {
	m, err := icmp.ParseMessage(1, b)
	if err != nil {
		return 0, 0, false, false
	}
	switch body := m.Body.(type) {
	case *icmp.Echo:
		return body.ID, body.Seq, m.Type == ipv4.ICMPTypeEchoReply, m.Type == ipv4.ICMPTypeEchoReply
	case *icmp.TimeExceeded:
		return quoted(body.Data)
	case *icmp.DstUnreach:
		return quoted(body.Data)
	}
	return 0, 0, false, false
}

// quoted finds our echo in the original datagram an ICMP error carries.
func quoted(d []byte) (id, seq int, reply, ok bool) {
	if len(d) < 20 {
		return 0, 0, false, false
	}
	ihl := int(d[0]&0x0f) * 4
	if d[0]>>4 != 4 || ihl < 20 || len(d) < ihl+8 || d[9] != 1 || d[ihl] != byte(ipv4.ICMPTypeEcho) {
		return 0, 0, false, false
	}
	return int(binary.BigEndian.Uint16(d[ihl+4:])), int(binary.BigEndian.Uint16(d[ihl+6:])), false, true
}
