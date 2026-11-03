package gnmi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const (
	maxTargets       = 100
	maxPaths         = 50
	maxUpdatesPerMsg = 10_000
	maxMsgBytes      = 16 << 20
	subscribeMethod  = "/gnmi.gNMI/Subscribe"
)

// Target is one device. Credentials live in a file, are sent only as gRPC metadata on this
// device's TLS connection and are refused over plaintext.
type Target struct {
	Name               string   `json:"name"`
	Address            string   `json:"address"` // host:port
	Username           string   `json:"username"`
	PasswordFile       string   `json:"password_file"`
	CAFile             string   `json:"ca_file"`
	ServerName         string   `json:"server_name"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	Plaintext          bool     `json:"plaintext"` // no TLS at all: lab use, never with credentials
	Paths              []string `json:"paths"`
	Prefix             string   `json:"prefix"`
	Mode               string   `json:"mode"`            // sample (default) or on_change
	SampleInterval     string   `json:"sample_interval"` // default 30s, at least 1s
	Encoding           string   `json:"encoding"`        // json_ietf (default), json or proto
}

// Config is the gnmi module's config. Remote config may only set enabled and interval.
type Config struct {
	Enabled  *bool    `json:"enabled"`
	Interval string   `json:"interval"` // unused: the device pushes; kept for the toggle overlay
	Targets  []Target `json:"targets"`
}

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.(*[]byte); ok {
		return *b, nil
	}
	return nil, fmt.Errorf("gnmi codec: cannot marshal %T", v)
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	if b, ok := v.(*[]byte); ok {
		*b = append((*b)[:0], data...)
		return nil
	}
	return fmt.Errorf("gnmi codec: cannot unmarshal into %T", v)
}

// request builds the subscription of a target.
func (t Target) request() ([]byte, error) {
	if len(t.Paths) == 0 || len(t.Paths) > maxPaths {
		return nil, fmt.Errorf("gnmi %q: 1 to %d paths", t.Name, maxPaths)
	}
	mode := ModeSample
	switch t.Mode {
	case "", "sample":
	case "on_change":
		mode = ModeOnChange
	default:
		return nil, fmt.Errorf("gnmi %q: mode is sample or on_change", t.Name)
	}
	enc := EncodingJSONIETF
	switch t.Encoding {
	case "", "json_ietf":
	case "json":
		enc = EncodingJSON
	case "proto":
		enc = EncodingProto
	default:
		return nil, fmt.Errorf("gnmi %q: encoding is json_ietf, json or proto", t.Name)
	}
	every := host.Duration(t.SampleInterval, 30*time.Second, time.Second)
	var subs []Sub
	for _, s := range t.Paths {
		p, err := ParsePath(s)
		if err != nil {
			return nil, err
		}
		sub := Sub{Path: p, Mode: mode}
		if mode == ModeSample {
			sub.SampleNS = uint64(every.Nanoseconds()) //nolint:gosec // positive
		}
		subs = append(subs, sub)
	}
	prefix, err := ParsePath(t.Prefix)
	if err != nil {
		return nil, err
	}
	return SubscribeRequest(prefix, subs, enc), nil
}

func (t Target) dialOptions() ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{grpc.WithNoProxy(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgBytes))}
	if t.Plaintext {
		if t.Username != "" || t.PasswordFile != "" {
			return nil, fmt.Errorf("gnmi %q: credentials are never sent without TLS", t.Name)
		}
		return append(opts, grpc.WithTransportCredentials(insecure.NewCredentials())), nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.ServerName, InsecureSkipVerify: t.InsecureSkipVerify} //nolint:gosec // local opt-in for self-signed devices
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("gnmi %q: ca_file cannot be read", t.Name)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gnmi %q: ca_file has no certificates", t.Name)
		}
		tc.RootCAs = pool
	}
	return append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tc))), nil
}

func (t Target) authContext(ctx context.Context) (context.Context, error) {
	if t.Username == "" {
		return ctx, nil
	}
	pw := ""
	if t.PasswordFile != "" {
		b, err := os.ReadFile(t.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("gnmi %q: password_file cannot be read", t.Name)
		}
		pw = strings.TrimRight(string(b), "\r\n")
	}
	return metadata.AppendToOutgoingContext(ctx, "username", t.Username, "password", pw), nil
}

// Subscribe runs one subscription until the stream ends or ctx is done.
func Subscribe(ctx context.Context, t Target, out sink.Sink) error {
	req, err := t.request()
	if err != nil {
		return err
	}
	opts, err := t.dialOptions()
	if err != nil {
		return err
	}
	cc, err := grpc.NewClient("passthrough:///"+t.Address, opts...)
	if err != nil {
		return fmt.Errorf("gnmi %q: bad address", t.Name)
	}
	defer cc.Close()
	sctx, err := t.authContext(ctx)
	if err != nil {
		return err
	}
	st, err := cc.NewStream(sctx, &grpc.StreamDesc{StreamName: "Subscribe", ServerStreams: true, ClientStreams: true},
		subscribeMethod, grpc.ForceCodec(rawCodec{}))
	if err != nil {
		return fmt.Errorf("gnmi %q: subscribe failed", t.Name)
	}
	if err := st.SendMsg(&req); err != nil {
		return fmt.Errorf("gnmi %q: subscribe failed", t.Name)
	}
	base := map[string]string{"gnmi.target": t.Name}
	out.Gauge("gnmi.target.up", "1", 1, base, time.Now())
	for {
		var msg []byte
		if err := st.RecvMsg(&msg); err != nil {
			out.Gauge("gnmi.target.up", "1", 0, base, time.Now())
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("gnmi %q: stream ended", t.Name) // the status text could hold device detail
		}
		n, _, err := DecodeResponse(msg, maxUpdatesPerMsg)
		if err != nil {
			return fmt.Errorf("gnmi %q: %w", t.Name, err)
		}
		if n != nil {
			Emit(out, base, n)
		}
	}
}

// metricName turns /interfaces/interface/state/counters/in-octets into
// gnmi.interfaces.interface.state.counters.in_octets.
func metricName(p Path) string {
	var b strings.Builder
	b.WriteString("gnmi")
	for _, e := range p.Elems {
		b.WriteByte('.')
		name := e.Name
		if _, after, ok := strings.Cut(name, ":"); ok { // openconfig-interfaces:interfaces
			name = after
		}
		for _, c := range name {
			if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' {
				b.WriteRune(unicode.ToLower(c))
			} else {
				b.WriteByte('_')
			}
		}
	}
	return sink.Truncate(b.String(), 255)
}

// stateValues maps the common enumerated leaves (oper-status, admin-status, session-state) to
// numbers: up/established 1, everything else 0.
var stateValues = map[string]float64{"UP": 1, "DOWN": 0, "ESTABLISHED": 1, "TRUE": 1, "FALSE": 0,
	"IDLE": 0, "CONNECT": 0, "ACTIVE": 0, "OPENSENT": 0, "OPENCONFIRM": 0, "LOWER_LAYER_DOWN": 0, "NOT_PRESENT": 0, "DORMANT": 0, "TESTING": 0, "UNKNOWN": 0}

// Emit writes the numeric leaves of a notification: counters (paths under "counters") as sums,
// the rest as gauges. Path keys become gnmi.<element>.<key> attributes.
func Emit(out sink.Sink, base map[string]string, n *Notification) {
	at := time.Now()
	if n.TimestampNS > 0 {
		at = time.Unix(0, n.TimestampNS)
	}
	for _, u := range n.Updates {
		v, ok := u.Value.Num, u.Value.IsNum
		if !ok {
			s := strings.ToUpper(u.Value.Str)
			if _, after, found := strings.Cut(s, ":"); found { // openconfig-bgp-types:ESTABLISHED
				s = after
			}
			v, ok = stateValues[s]
		}
		if !ok || len(u.Path.Elems) == 0 {
			continue
		}
		a := sink.With(base)
		counter := false
		for _, e := range u.Path.Elems {
			if e.Name == "counters" {
				counter = true
			}
			for k, kv := range e.Keys {
				a["gnmi."+e.Name+"."+k] = sink.Truncate(kv, 256)
			}
		}
		name := metricName(u.Path)
		if counter {
			out.Sum(name, "", v, a, at)
		} else {
			out.Gauge(name, "", v, a, at)
		}
	}
}

// Run keeps one subscription per target, reconnecting with backoff, until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("gnmi config: %w", err)
		}
	}
	if len(c.Targets) > maxTargets {
		return errors.New("gnmi: too many targets")
	}
	for _, t := range c.Targets {
		if t.Name == "" || t.Address == "" {
			return errors.New("gnmi: every target needs name and address")
		}
		if _, err := t.request(); err != nil {
			return err
		}
		if _, err := t.dialOptions(); err != nil {
			return err
		}
	}
	if c.Enabled != nil && !*c.Enabled || len(c.Targets) == 0 {
		<-ctx.Done()
		return nil
	}
	var wg sync.WaitGroup
	for _, t := range c.Targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; ctx.Err() == nil; attempt++ {
				start := time.Now()
				if err := Subscribe(ctx, t, out); err != nil {
					slog.Warn("gnmi subscription", "target", t.Name, "error", err)
				}
				if time.Since(start) > time.Minute {
					attempt = 0 // a stream that ran a while resets the backoff
				}
				select {
				case <-ctx.Done():
				case <-time.After(sink.Backoff(attempt, rand.Float64())): //nolint:gosec // jitter
				}
			}
		}()
	}
	wg.Wait()
	return nil
}
