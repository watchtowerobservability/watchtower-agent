package relay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/logs"
	"github.com/watchtowerobservability/watchtower-agent/internal/srcconv"
)

// startSyslog serves RFC 5424 and RFC 3164 over UDP and TCP (newline or octet-counted framing),
// reusing the agent's parser and listeners (agent/logs).
func (r *Relay) startSyslog(ctx context.Context, s SourceConfig) error {
	// Bind here so a bad address fails startup, not the background goroutine.
	if s.UDP != "" {
		pc, err := net.ListenPacket("udp", s.UDP)
		if err != nil {
			return err
		}
		_ = pc.Close()
	}
	if s.TCP != "" {
		l, err := net.Listen("tcp", s.TCP)
		if err != nil {
			return err
		}
		_ = l.Close()
	}
	b := newLogBatcher(ctx, r)
	go func() {
		if err := logs.RunSyslog(ctx, logs.SyslogConf{UDP: s.UDP, TCP: s.TCP}, b); err != nil {
			slog.Error("relay syslog source stopped", "error", err)
		}
	}()
	return nil
}

// startKafka consumes topics as logs (one record value = one line; JSON values keep their string
// fields as attributes). Offsets are committed only after the batch is in the disk queue, so
// delivery is at-least-once; while the queue refuses writes the consumer waits and retries.
func (r *Relay) startKafka(ctx context.Context, s SourceConfig) error {
	c := logs.KafkaLogs{Brokers: s.Brokers, Topics: s.Topics, Group: s.Group, TLS: s.TLS}
	if c.Group == "" {
		c.Group = "wt-relay"
	}
	if s.SASLUsername != "" {
		pw, err := secret("", s.SASLPasswordFile)
		if err != nil || pw == "" {
			return errors.New("sasl_password_file is empty or unreadable")
		}
		c.SASL = &struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{s.SASLUsername, pw}
	}
	go func() {
		err := logs.RunKafkaBatches(ctx, c, func(ctx context.Context, recs []*kgo.Record) error {
			col := &collectSink{}
			for _, rec := range recs {
				logs.KafkaRecord(col, rec)
			}
			return r.retryLogs(ctx, col.recs)
		})
		if err != nil && ctx.Err() == nil {
			slog.Error("relay kafka source stopped", "error", err)
		}
	}()
	return nil
}

// retryLogs enqueues recs, waiting 1 s between attempts while the queue is unavailable.
func (r *Relay) retryLogs(ctx context.Context, recs []*logspb.LogRecord) error {
	for {
		err := r.logsChunked(recs)
		if err == nil {
			return nil
		}
		slog.Warn("relay kafka source: queue unavailable, retrying", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// collectSink gathers the records of one batch (agent sink.Sink contract).
type collectSink struct{ recs []*logspb.LogRecord }

func (c *collectSink) Gauge(string, string, float64, map[string]string, time.Time) {}
func (c *collectSink) Sum(string, string, float64, map[string]string, time.Time)   {}
func (c *collectSink) Log(sev, body string, attrs map[string]string, at time.Time) {
	c.recs = append(c.recs, logRec(sev, body, attrs, at))
}

// ---- Fluent forward ---------------------------------------------------------------------------

const (
	fluentMaxMsg  = 16 << 20
	fluentIdle    = 5 * time.Minute
	fluentMaxConn = 256
)

// startFluent serves the Fluent forward protocol (Fluentd out_forward, Fluent Bit forward output)
// over TCP: Message, Forward, PackedForward and gzip CompressedPackedForward modes, with chunk
// acknowledgements. With a shared key the HELO/PING/PONG handshake runs first (shared_key
// authentication; username/password auth is not offered), and cert_file/key_file serve it over TLS.
func (r *Relay) startFluent(ctx context.Context, addr, key string, tlsCfg *tls.Config) error {
	l, err := listen(addr, tlsCfg)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	go func() {
		sem := make(chan struct{}, fluentMaxConn)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case sem <- struct{}{}:
			default:
				_ = c.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done(); _ = c.Close() }()
				r.fluentConn(ctx, c, key)
			}()
		}
	}()
	return nil
}

func (r *Relay) fluentConn(ctx context.Context, c net.Conn, key string) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReaderSize(c, 64<<10)
	var buf []byte
	authed, nonce := key == "", []byte(nil)
	if !authed {
		nonce = make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(fluentHelo(nonce)); err != nil {
			return
		}
	}
	chunk := make([]byte, 64<<10)
	for {
		v, rest, err := srcconv.MsgpackNext(buf, true)
		switch {
		case err == nil:
			buf = rest
			if !authed {
				resp, ok := fluentPing(v, nonce, key)
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, werr := c.Write(resp); werr != nil || !ok {
					return
				}
				authed = true
				continue
			}
			ack, herr := r.fluentMessage(ctx, v)
			if herr != nil {
				slog.Warn("relay fluent message rejected", "error", herr)
				return // no ack: the sender retries
			}
			if ack != nil {
				if _, err := c.Write(ack); err != nil {
					return
				}
			}
			continue
		case errors.Is(err, srcconv.ErrMsgpackShort) && len(buf) < fluentMaxMsg:
		default:
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(fluentIdle))
		n, err := br.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil && n == 0 {
			return
		}
	}
}

// fluentMessage handles one decoded forward message and returns the ack to send (nil = none).
func (r *Relay) fluentMessage(ctx context.Context, v any) ([]byte, error) {
	m, _ := v.([]any)
	if v == nil || len(m) == 0 { // heartbeat
		return nil, nil
	}
	if len(m) < 2 {
		return nil, srcconv.ErrDatadog
	}
	tag, _ := m[0].(string)
	// the option map follows the events, or the record in Message mode (then it is m[3])
	var opt map[string]any
	optAt := 2
	switch m[1].(type) {
	case []any, []byte, string:
	default:
		optAt = 3
	}
	if len(m) > optAt {
		opt, _ = m[optAt].(map[string]any)
	}
	var recs []*logspb.LogRecord
	now := uint64(time.Now().UnixNano()) //nolint:gosec // positive
	add := func(ts, rec any) {
		if mp, ok := rec.(map[string]any); ok {
			recs = append(recs, fluentRecord(tag, ts, mp, now))
		}
	}
	switch body := m[1].(type) {
	case []any: // Forward: [tag, [[time, record], ...], option]
		for _, e := range body {
			if pair, _ := e.([]any); len(pair) == 2 {
				add(pair[0], pair[1])
			}
		}
	case []byte, string: // PackedForward: a stream of [time, record]
		packed := []byte(srcconv.MPStr(body))
		if opt["compressed"] == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(packed))
			if err != nil {
				return nil, err
			}
			if packed, err = io.ReadAll(io.LimitReader(zr, fluentMaxMsg+1)); err != nil || len(packed) > fluentMaxMsg {
				return nil, errors.New("bad compressed forward payload")
			}
		}
		for len(packed) > 0 {
			e, rest, err := srcconv.MsgpackNext(packed, true)
			if err != nil {
				return nil, err
			}
			packed = rest
			if pair, _ := e.([]any); len(pair) == 2 {
				add(pair[0], pair[1])
			}
		}
	default: // Message: [tag, time, record, option]
		if len(m) < 3 {
			return nil, srcconv.ErrDatadog
		}
		add(m[1], m[2])
	}
	if len(recs) > 0 {
		if err := r.Logs(logsReq(recs)); err != nil {
			return nil, err
		}
	}
	if id := srcconv.MPStr(opt["chunk"]); id != "" && len(id) < 256 {
		return fluentAck(id), nil
	}
	return nil, nil
}

// fluentRecord maps one event; time is seconds (int or float) or the EventTime extension.
func fluentRecord(tag string, ts any, rec map[string]any, now uint64) *logspb.LogRecord {
	var ns uint64
	switch t := ts.(type) {
	case time.Time:
		ns = uint64(t.UnixNano()) //nolint:gosec // positive for real clocks
	case uint64:
		ns = t * 1e9
	case int64:
		if t > 0 {
			ns = uint64(t) * 1e9
		}
	case float64:
		if t > 0 {
			ns = uint64(t * 1e9)
		}
	}
	rec = jsonish(rec).(map[string]any)
	lr := srcconv.JSONLogRecord(rec, []string{"log", "message", "msg"}, ns, now)
	lr.Attributes = srcconv.AppendKV(lr.Attributes, "fluent.tag", srcconv.StrVal(tag))
	if lvl, _ := rec["level"].(string); lvl != "" {
		srcconv.SetSeverity(lr, lvl)
	}
	return lr
}

// jsonish rewrites msgpack scalars as the JSON decoder's types (numbers as json.Number, bin as
// string) so the shared JSON converters apply.
func jsonish(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonish(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonish(e)
		}
		return out
	case []byte:
		return string(x)
	case uint64:
		return json.Number(strconv.FormatUint(x, 10))
	case int64:
		return json.Number(strconv.FormatInt(x, 10))
	case float64:
		return json.Number(strconv.FormatFloat(x, 'g', -1, 64))
	case time.Time:
		return x.Format(time.RFC3339Nano)
	}
	return v
}

// fluentAck is the msgpack map {"ack": <chunk>}.
func fluentAck(chunk string) []byte {
	out := []byte{0x81, 0xa3, 'a', 'c', 'k'}
	if len(chunk) < 32 {
		out = append(out, 0xa0|byte(len(chunk))) //nolint:gosec // < 32
	} else {
		out = append(out, 0xd9, byte(len(chunk))) //nolint:gosec // chunk ids are short
	}
	return append(out, chunk...)
}

// ---- shared_key handshake (Fluentd forward protocol v1) ----

// mpStr encodes a msgpack string.
func mpStr(s string) []byte {
	switch n := len(s); {
	case n < 32:
		return append([]byte{0xa0 | byte(n)}, s...) //nolint:gosec // < 32
	case n < 256:
		return append([]byte{0xd9, byte(n)}, s...) //nolint:gosec // < 256
	default:
		return append([]byte{0xda, byte(n >> 8), byte(n)}, s...) //nolint:gosec // short strings only
	}
}

// fluentHelo is ["HELO", {"nonce": bin, "auth": bin(""), "keepalive": true}].
func fluentHelo(nonce []byte) []byte {
	out := append([]byte{0x92}, mpStr("HELO")...)
	out = append(out, 0x83)
	out = append(out, mpStr("nonce")...)
	out = append(out, 0xc4, byte(len(nonce))) //nolint:gosec // 16
	out = append(out, nonce...)
	out = append(out, mpStr("auth")...)
	out = append(out, 0xc4, 0)
	out = append(out, mpStr("keepalive")...)
	return append(out, 0xc3)
}

func sha512Hex(parts ...[]byte) string {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fluentPing verifies the client's ["PING", host, salt, digest, user, pwdigest] and returns the
// PONG to send; ok is false when authentication failed (the PONG then says so and the connection closes).
func fluentPing(v any, nonce []byte, key string) (pong []byte, ok bool) {
	host, _ := os.Hostname()
	deny := func(reason string) ([]byte, bool) {
		out := append([]byte{0x95}, mpStr("PONG")...)
		out = append(out, 0xc2)
		out = append(out, mpStr(reason)...)
		out = append(out, mpStr(host)...)
		return append(out, mpStr("")...), false
	}
	m, _ := v.([]any)
	if len(m) < 4 || srcconv.MPStr(m[0]) != "PING" {
		return deny("invalid ping message")
	}
	clientHost, salt := []byte(srcconv.MPStr(m[1])), []byte(srcconv.MPStr(m[2]))
	want := sha512Hex(salt, clientHost, nonce, []byte(key))
	if subtle.ConstantTimeCompare([]byte(want), []byte(srcconv.MPStr(m[3]))) != 1 {
		return deny("shared_key mismatch")
	}
	out := append([]byte{0x95}, mpStr("PONG")...)
	out = append(out, 0xc3)
	out = append(out, mpStr("")...)
	out = append(out, mpStr(host)...)
	return append(out, mpStr(sha512Hex(salt, []byte(host), nonce, []byte(key)))...), true
}
