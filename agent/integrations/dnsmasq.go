package integrations

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// DnsmasqConfig is the dnsmasq DNS address (host:port, default 127.0.0.1:53).
type DnsmasqConfig struct {
	Base
	Address string `json:"address"`
}

func (c *DnsmasqConfig) check() error {
	if c.Address == "" {
		c.Address = "127.0.0.1:53"
	}
	_, _, err := net.SplitHostPort(c.Address)
	return err
}

var dnsmasqStats = []string{"cachesize", "insertions", "evictions", "misses", "hits"}

// Dnsmasq asks dnsmasq's CHAOS-class TXT names (cachesize.bind, hits.bind, ...) for its cache counters.
func Dnsmasq(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &DnsmasqConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "dnsmasq", c.Base, 30*time.Second, out, func(ctx context.Context, now time.Time) error {
		for i, s := range dnsmasqStats {
			v, err := chaosTXT(ctx, c.Address, s+".bind", uint16(i+1))
			if err != nil {
				return err
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			if s == "cachesize" {
				out.Gauge("dnsmasq.cache.size", "{entries}", f, nil, now)
			} else {
				out.Sum("dnsmasq.cache."+s, "1", f, nil, now)
			}
		}
		return nil
	})
}

// chaosQuery builds a DNS query for name, class CHAOS (3), type TXT (16).
func chaosQuery(name string, id uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) // RD, one question
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 16, 0, 3)
}

// parseChaosTXT returns the first TXT string of the first answer.
func parseChaosTXT(b []byte, id uint16) (string, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || binary.BigEndian.Uint16(b[6:]) == 0 {
		return "", errors.New("dnsmasq: no answer")
	}
	p := 12
	for p < len(b) && b[p] != 0 { // skip the question name
		p += int(b[p]) + 1
	}
	p += 5 // root label, qtype, qclass
	if p < len(b) && b[p]&0xC0 == 0xC0 {
		p += 2
	} else {
		for p < len(b) && b[p] != 0 {
			p += int(b[p]) + 1
		}
		p++
	}
	p += 10 // type, class, ttl, rdlength
	if p >= len(b) || p+1+int(b[p]) > len(b) {
		return "", errors.New("dnsmasq: short answer")
	}
	return string(b[p+1 : p+1+int(b[p])]), nil
}

func chaosTXT(ctx context.Context, addr, name string, id uint16) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(chaosQuery(name, id)); err != nil {
		return "", err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", errors.New("dnsmasq: no reply from " + addr)
	}
	return parseChaosTXT(buf[:n], id)
}
