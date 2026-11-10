package integrations

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// NTPConfig is the ntp module config: the servers to query (host or host:port; port 123).
type NTPConfig struct {
	Base
	Servers []string `json:"servers"`
}

func (c *NTPConfig) check() error {
	if len(c.Servers) == 0 {
		return errors.New("servers is required (in the agent's own config file)")
	}
	return nil
}

const ntpEpochOffset = 2208988800 // seconds between 1900-01-01 and 1970-01-01

// NTP queries each server with one SNTP request per round and reports `ntp.offset` (positive:
// the local clock is behind), `ntp.offset_abs`, `ntp.delay` and `ntp.stratum` per server.
func NTP(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	c := &NTPConfig{}
	if err := load(raw, c); err != nil {
		return err
	}
	return Loop(ctx, "ntp", c.Base, 60*time.Second, out, func(ctx context.Context, now time.Time) error {
		var firstErr error
		for _, s := range c.Servers {
			off, delay, stratum, err := sntpQuery(ctx, s)
			if err != nil {
				firstErr = errors.Join(firstErr, errors.New("ntp "+s+": "+err.Error()))
				continue
			}
			a := map[string]string{"server": s}
			out.Gauge("ntp.offset", "s", off, a, now)
			out.Gauge("ntp.offset_abs", "s", math.Abs(off), a, now)
			out.Gauge("ntp.delay", "s", delay, a, now)
			out.Gauge("ntp.stratum", "1", float64(stratum), a, now)
		}
		return firstErr
	})
}

func toNTP(t time.Time) uint64 {
	return uint64(t.Unix()+ntpEpochOffset)<<32 | uint64(float64(t.Nanosecond())/1e9*(1<<32))
}

func fromNTP(v uint64) time.Time {
	return time.Unix(int64(v>>32)-ntpEpochOffset, int64(float64(v&0xffffffff)/(1<<32)*1e9))
}

func sntpQuery(ctx context.Context, server string) (offset, delay float64, stratum int, err error) {
	if _, _, e := net.SplitHostPort(server); e != nil {
		server = net.JoinHostPort(server, "123")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, 0, 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	req := make([]byte, 48)
	req[0] = 0x23 // LI 0, version 4, mode 3 (client)
	t0 := time.Now()
	binary.BigEndian.PutUint64(req[40:], toNTP(t0))
	if _, err = conn.Write(req); err != nil {
		return 0, 0, 0, err
	}
	resp := make([]byte, 48)
	if n, e := conn.Read(resp); e != nil || n < 48 {
		return 0, 0, 0, errors.New("no reply")
	}
	t3 := time.Now()
	if resp[0]&7 != 4 && resp[0]&7 != 5 {
		return 0, 0, 0, errors.New("not a server reply")
	}
	if resp[1] == 0 {
		return 0, 0, 0, errors.New("kiss-of-death reply")
	}
	t1, t2 := fromNTP(binary.BigEndian.Uint64(resp[32:])), fromNTP(binary.BigEndian.Uint64(resp[40:]))
	offset = (t1.Sub(t0).Seconds() + t2.Sub(t3).Seconds()) / 2
	delay = t3.Sub(t0).Seconds() - t2.Sub(t1).Seconds()
	return offset, delay, int(resp[1]), nil
}
