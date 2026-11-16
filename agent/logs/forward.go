package logs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/internal/srcconv"
)

// ForwardConf is `logs.forward`: a Fluent forward listener for Docker's fluentd log driver, the
// socket-free way to collect container logs. Local file only.
type ForwardConf struct {
	// Listen is the TCP address, e.g. 127.0.0.1:24224 (network_mode host) or 0.0.0.0:24224 inside
	// a container whose port is published only on the host loopback.
	Listen string `json:"listen"`
	// Labels keeps only records whose container labels (log-opt labels/labels-regex) match.
	Labels container.LabelSet `json:"labels"`
}

const (
	fwdMaxMsg  = 4 << 20
	fwdIdle    = 5 * time.Minute
	fwdMaxConn = 64
)

// Fields the fluentd driver sets itself; every other string field is a label (or an opted-in env var).
var fwdReserved = map[string]bool{"log": true, "container_id": true, "container_name": true, "source": true,
	"partial_message": true, "partial_id": true, "partial_ordinal": true, "partial_last": true}

// FwdRecord is one container log line as the fluentd driver sends it.
type FwdRecord struct {
	ID, Name, Body, Stream string
	Labels                 map[string]string
	Env                    []string // OTEL_* variables only, for the service identity
}

// ParseForwardRecord reads a driver record; ok is false without a container id and a line.
func ParseForwardRecord(rec map[string]any) (FwdRecord, bool) {
	r := FwdRecord{ID: srcconv.MPStr(rec["container_id"]), Body: srcconv.MPStr(rec["log"]),
		Name: strings.TrimPrefix(srcconv.MPStr(rec["container_name"]), "/"), Stream: srcconv.MPStr(rec["source"]),
		Labels: map[string]string{}}
	for k, v := range rec {
		s, isStr := v.(string)
		if b, ok := v.([]byte); ok {
			s, isStr = string(b), true
		}
		switch {
		case fwdReserved[k] || !isStr:
		case strings.HasPrefix(k, "OTEL_"):
			r.Env = append(r.Env, k+"="+s) // never kept as a label or attribute
		default:
			r.Labels[k] = s
		}
	}
	return r, r.ID != "" && len(r.ID) >= 12 && r.Body != ""
}

// Apply learns the container (name, service, labels: they name and label its cgroup series) and
// emits the line with the attributes the docker logs module uses, unless the labels filter drops it.
func (r FwdRecord) Apply(want container.LabelSet, out sink.Sink, at time.Time) {
	if !container.HasLabels(r.Labels, want) {
		return
	}
	svc := r.Labels[container.ComposeServiceLabel]
	if svc == "" {
		svc = container.ServiceFromName(r.Name)
	}
	container.Learn(r.ID, container.Learned{Name: r.Name, Service: svc, Labels: r.Labels})
	labels := sink.With(r.Labels, container.ComposeServiceLabel, svc)
	attrs := map[string]string{"container.id": r.ID, "container.name": r.Name}
	for k, v := range sink.Res(container.ResolveIdentity(r.Env, labels, nil, r.Name).Resource()) {
		attrs[k] = v
	}
	if r.Stream != "" {
		attrs["log.iostream"] = r.Stream
	}
	out.Log(Severity(r.Body), r.Body, attrs, at)
}

// RunForward serves the Fluent forward protocol (Message, Forward and PackedForward modes, with
// chunk acks) until ctx ends.
func RunForward(ctx context.Context, c ForwardConf, out sink.Sink) error {
	if c.Listen == "" {
		return errors.New("logs.forward.listen is not set")
	}
	l, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	slog.Info("logs: fluent forward listener started", "listen", c.Listen, "labels", container.LabelFilter(c.Labels))
	sem := make(chan struct{}, fwdMaxConn)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			return nil
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done(); _ = conn.Close() }()
			fwdConn(conn, c, out)
		}()
	}
}

func fwdConn(conn net.Conn, c ForwardConf, out sink.Sink) {
	var buf []byte
	chunk := make([]byte, 64<<10)
	for {
		v, rest, err := srcconv.MsgpackNext(buf, true)
		switch {
		case err == nil:
			buf = rest
			ack, herr := fwdMessage(v, c, out)
			if herr != nil {
				slog.Warn("logs forward: message rejected", "error", herr)
				return // no ack: the driver retries
			}
			if ack != nil {
				if _, err := conn.Write(ack); err != nil {
					return
				}
			}
			continue
		case errors.Is(err, srcconv.ErrMsgpackShort) && len(buf) < fwdMaxMsg:
		default:
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(fwdIdle))
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil && n == 0 {
			return
		}
	}
}

// fwdMessage handles one decoded message and returns the ack to send (nil: none).
func fwdMessage(v any, c ForwardConf, out sink.Sink) ([]byte, error) {
	m, _ := v.([]any)
	if len(m) == 0 {
		return nil, nil // heartbeat
	}
	if len(m) < 3 {
		return nil, fmt.Errorf("short forward message")
	}
	optAt := 2
	switch m[1].(type) {
	case []any, []byte, string:
	default:
		optAt = 3
	}
	var opt map[string]any
	if len(m) > optAt {
		opt, _ = m[optAt].(map[string]any)
	}
	add := func(ts, rec any) {
		mp, _ := rec.(map[string]any)
		if r, ok := ParseForwardRecord(mp); ok {
			r.Apply(c.Labels, out, fwdTime(ts))
		}
	}
	switch body := m[1].(type) {
	case []any: // Forward: [tag, [[time, record], ...], option]
		for _, e := range body {
			if p, _ := e.([]any); len(p) == 2 {
				add(p[0], p[1])
			}
		}
	case []byte, string: // PackedForward: a stream of [time, record]
		packed := []byte(srcconv.MPStr(body))
		if opt["compressed"] != nil && opt["compressed"] != "text" {
			return nil, errors.New("compressed forward is not supported: drop the driver's compress option")
		}
		for len(packed) > 0 {
			e, rest, err := srcconv.MsgpackNext(packed, true)
			if err != nil {
				return nil, err
			}
			packed = rest
			if p, _ := e.([]any); len(p) == 2 {
				add(p[0], p[1])
			}
		}
	default: // Message: [tag, time, record, option]
		add(m[1], m[2])
	}
	if id := srcconv.MPStr(opt["chunk"]); id != "" && len(id) < 32 {
		return append([]byte{0x81, 0xa3, 'a', 'c', 'k', 0xa0 | byte(len(id))}, id...), nil //nolint:gosec // < 32
	}
	return nil, nil
}

func fwdTime(ts any) time.Time {
	switch t := ts.(type) {
	case time.Time:
		return t
	case uint64:
		return time.Unix(int64(t), 0) //nolint:gosec // seconds
	case int64:
		return time.Unix(t, 0)
	case float64:
		return time.Unix(int64(t), 0)
	}
	return time.Now()
}
