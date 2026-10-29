package logs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxSyslogTCPConns = 256
	maxSyslogMsg      = 64 << 10
	syslogIdle        = 5 * time.Minute
)

// SyslogConf makes the agent a syslog receiver. Addresses come from the local file only. The
// listener is unauthenticated: bind it to loopback or a trusted interface, and use a port above
// 1024 for an unprivileged agent.
type SyslogConf struct {
	UDP string `json:"udp"` // e.g. "127.0.0.1:5514"
	TCP string `json:"tcp"`
}

var facilities = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
	"authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3",
	"local4", "local5", "local6", "local7"}

var syslogSeverity = [8]string{"ERROR", "ERROR", "ERROR", "ERROR", "WARN", "INFO", "INFO", "DEBUG"}

// ParseSyslog parses an RFC 5424 or RFC 3164 message. year/location defaults for the old format
// (which carries neither) come from now.
func ParseSyslog(msg string, now time.Time) (Record, error) {
	msg = strings.TrimRight(msg, "\r\n\x00")
	if !strings.HasPrefix(msg, "<") {
		return Record{}, errors.New("syslog: missing <PRI>")
	}
	end := strings.IndexByte(msg, '>')
	if end < 2 || end > 4 {
		return Record{}, errors.New("syslog: bad <PRI>")
	}
	pri, err := strconv.Atoi(msg[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return Record{}, errors.New("syslog: bad PRI value")
	}
	rest := msg[end+1:]
	attrs := map[string]string{"log.source": "syslog", "syslog.facility": facilities[pri/8]}
	r := Record{Severity: syslogSeverity[pri%8], At: now, Attrs: attrs}
	if len(rest) > 2 && rest[0] == '1' && rest[1] == ' ' {
		return parse5424(r, rest[2:])
	}
	return parse3164(r, rest, now)
}

// parse5424: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]
func parse5424(r Record, s string) (Record, error) {
	f := strings.SplitN(s, " ", 6)
	if len(f) < 6 {
		return Record{}, errors.New("syslog5424: too few fields")
	}
	if f[0] != "-" {
		t, err := time.Parse(time.RFC3339Nano, f[0])
		if err != nil {
			return Record{}, fmt.Errorf("syslog5424 timestamp: %w", err)
		}
		r.At = t
	}
	for i, k := range []string{"syslog.hostname", "syslog.app", "process.pid", "syslog.msgid"} {
		if f[i+1] != "-" {
			r.Attrs[k] = f[i+1]
		}
	}
	rest := f[5]
	if strings.HasPrefix(rest, "-") {
		rest = strings.TrimPrefix(strings.TrimPrefix(rest, "-"), " ")
	} else if strings.HasPrefix(rest, "[") {
		rest = strings.TrimPrefix(skipStructuredData(rest), " ")
	} else {
		return Record{}, errors.New("syslog5424: bad structured data")
	}
	rest = strings.TrimPrefix(rest, "\xef\xbb\xbf") // optional UTF-8 BOM
	r.Body = rest
	return r, nil
}

// skipStructuredData returns s after the run of [id k="v"...] elements, honouring \" \] \\ escapes.
func skipStructuredData(s string) string {
	i := 0
	for i < len(s) && s[i] == '[' {
		i++
		for i < len(s) && s[i] != ']' {
			if s[i] == '\\' {
				i++
			}
			i++
		}
		i++ // the closing ]
	}
	if i > len(s) {
		return ""
	}
	return s[i:]
}

// parse3164: "Mmm dd hh:mm:ss HOST TAG[pid]: msg" (the host and tag are best effort).
func parse3164(r Record, s string, now time.Time) (Record, error) {
	if len(s) >= 16 && s[3] == ' ' && s[6] == ' ' && s[9] == ':' {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", s[:15], time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) { // December message read in January
				t = t.AddDate(-1, 0, 0)
			}
			r.At = t
			s = s[16:]
			if host, after, ok := strings.Cut(s, " "); ok {
				r.Attrs["syslog.hostname"] = host
				s = after
			}
			if tag, msg, ok := strings.Cut(s, ": "); ok && !strings.ContainsAny(tag, " ") {
				if name, pid, ok := strings.Cut(strings.TrimSuffix(tag, "]"), "["); ok {
					r.Attrs["process.pid"] = pid
					tag = name
				}
				r.Attrs["syslog.app"] = tag
				s = msg
			}
		}
	}
	r.Body = s
	return r, nil
}

// RunSyslog listens until ctx ends.
func RunSyslog(ctx context.Context, c SyslogConf, out sink.Sink) error {
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	if c.UDP != "" {
		pc, err := net.ListenPacket("udp", c.UDP)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); pc.Close() }()
		wg.Add(1)
		go func() { defer wg.Done(); serveUDP(pc, out) }()
	}
	if c.TCP != "" {
		l, err := net.Listen("tcp", c.TCP)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); l.Close() }()
		wg.Add(1)
		go func() { defer wg.Done(); errs <- serveTCP(ctx, l, out) }()
	}
	wg.Wait()
	select {
	case err := <-errs:
		if ctx.Err() == nil {
			return err
		}
	default:
	}
	return nil
}

func serveUDP(pc net.PacketConn, out sink.Sink) {
	buf := make([]byte, maxSyslogMsg)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		deliver(string(buf[:n]), from, out)
	}
}

func serveTCP(ctx context.Context, l net.Listener, out sink.Sink) error {
	sem := make(chan struct{}, maxSyslogTCPConns)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close() // over the connection cap
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done(); c.Close() }()
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 4<<10), maxSyslogMsg)
			for {
				_ = c.SetReadDeadline(time.Now().Add(syslogIdle))
				if !sc.Scan() {
					return
				}
				deliver(stripOctetCount(sc.Text()), c.RemoteAddr(), out)
			}
		}()
	}
}

// stripOctetCount removes the RFC 6587 "<len> " prefix of octet-counted framing.
func stripOctetCount(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 && i < 7 {
		if _, err := strconv.Atoi(s[:i]); err == nil && strings.HasPrefix(s[i+1:], "<") {
			return s[i+1:]
		}
	}
	return s
}

func deliver(msg string, from net.Addr, out sink.Sink) {
	r, err := ParseSyslog(msg, time.Now())
	if err != nil {
		return
	}
	if from != nil {
		if ip, _, err := net.SplitHostPort(from.String()); err == nil {
			r.Attrs["net.peer.ip"] = ip
		}
	}
	r.send(out, nil)
}
