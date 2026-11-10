package relay

// Sources other than OTLP: Datadog Agent intake, Splunk HEC, syslog, Fluent forward and a Kafka
// topic. Each one converts to the relay's OTLP messages and calls Relay.Logs/Metrics/Traces, so
// processors, the disk queue and the destinations apply exactly as for OTLP senders.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"github.com/watchtowerobservability/watchtower-agent/internal/srcconv"
)

// Source types.
const (
	SrcDatadog = "datadog"
	SrcHEC     = "splunk_hec"
	SrcSyslog  = "syslog"
	SrcFluent  = "fluent_forward"
	SrcKafka   = "kafka"
)

// SourceConfig is one entry of `sources:` in the relay config.
type SourceConfig struct {
	Type string `yaml:"type"`
	// Listen is the TCP address of the http (datadog, splunk_hec) and fluent_forward types.
	Listen string `yaml:"listen"`
	// UDP and TCP are the syslog listen addresses (either or both).
	UDP string `yaml:"udp"`
	TCP string `yaml:"tcp"`
	// TokenFile holds the shared token senders must present (datadog: DD-API-KEY, splunk_hec:
	// `Authorization: Splunk <token>`); SharedKeyFile is the Fluent forward shared_key. A source
	// needs one of them, or AllowUnauthenticated: true (always, for syslog, which has no auth).
	TokenFile            string `yaml:"token_file"`
	SharedKeyFile        string `yaml:"shared_key_file"`
	AllowUnauthenticated bool   `yaml:"allow_unauthenticated"`
	// CertFile and KeyFile turn on TLS for the datadog, splunk_hec and fluent_forward listeners.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Kafka consumer group: brokers, topics, group (default wt-relay), tls and SASL/PLAIN.
	Brokers          []string `yaml:"brokers"`
	Topics           []string `yaml:"topics"`
	Group            string   `yaml:"group"`
	TLS              bool     `yaml:"tls"`
	SASLUsername     string   `yaml:"sasl_username"`
	SASLPasswordFile string   `yaml:"sasl_password_file"`
}

func (s SourceConfig) name(i int) string { return fmt.Sprintf("sources[%d] (%s)", i, s.Type) }

// validateSources checks the `sources:` list; used is the set of addresses already taken.
func validateSources(srcs []SourceConfig, used ...string) error {
	taken := map[string]string{}
	for _, a := range used {
		taken[a] = "a relay listener"
	}
	claim := func(who, addr string) error {
		if addr == "" {
			return nil
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s: %q is not host:port", who, addr)
		}
		if prev, dup := taken[addr]; dup {
			return fmt.Errorf("%s: %s is already used by %s", who, addr, prev)
		}
		taken[addr] = who
		return nil
	}
	for i, s := range srcs {
		who := s.name(i)
		switch s.Type {
		case SrcDatadog, SrcHEC, SrcFluent:
			if s.Listen == "" {
				return fmt.Errorf("%s: listen is required", who)
			}
			if err := claim(who, s.Listen); err != nil {
				return err
			}
		case SrcSyslog:
			if s.UDP == "" && s.TCP == "" {
				return fmt.Errorf("%s: udp or tcp is required", who)
			}
			if err := claim(who, s.TCP); err != nil {
				return err
			}
			if _, _, err := net.SplitHostPort(s.UDP); s.UDP != "" && err != nil {
				return fmt.Errorf("%s: %q is not host:port", who, s.UDP)
			}
		case SrcKafka:
			if len(s.Brokers) == 0 || len(s.Topics) == 0 {
				return fmt.Errorf("%s: brokers and topics are required", who)
			}
			if (s.SASLUsername == "") != (s.SASLPasswordFile == "") {
				return fmt.Errorf("%s: sasl_username and sasl_password_file go together", who)
			}
		default:
			return fmt.Errorf("sources[%d]: unknown type %q (datadog, splunk_hec, syslog, fluent_forward, kafka)", i, s.Type)
		}
		if err := validateSourceAuth(who, s); err != nil {
			return err
		}
	}
	return nil
}

func validateSourceAuth(who string, s SourceConfig) error {
	if s.TokenFile != "" && s.Type != SrcDatadog && s.Type != SrcHEC {
		return fmt.Errorf("%s: token_file is not supported (only datadog and splunk_hec; fluent_forward uses shared_key_file)", who)
	}
	if s.SharedKeyFile != "" && s.Type != SrcFluent {
		return fmt.Errorf("%s: shared_key_file is only for fluent_forward", who)
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		return fmt.Errorf("%s: cert_file and key_file go together", who)
	}
	tlsOK := s.Type == SrcDatadog || s.Type == SrcHEC || s.Type == SrcFluent
	if s.CertFile != "" && !tlsOK {
		return fmt.Errorf("%s: cert_file is not supported for %s", who, s.Type)
	}
	if s.Type == SrcKafka {
		return nil // the brokers authenticate the consumer (sasl_*)
	}
	authed := s.TokenFile != "" || s.SharedKeyFile != ""
	switch {
	case authed && s.AllowUnauthenticated:
		return fmt.Errorf("%s: allow_unauthenticated contradicts the configured token or key", who)
	case !authed && !s.AllowUnauthenticated:
		return fmt.Errorf("%s: no authentication configured: set token_file (shared_key_file for fluent_forward), or allow_unauthenticated: true to accept any sender that can reach the listener", who)
	}
	return nil
}

// StartSources starts every configured source and returns once all listeners are bound; they run
// until ctx ends. A fatal source error is logged (the OTLP receivers keep serving).
func (r *Relay) StartSources(ctx context.Context, srcs []SourceConfig) error {
	for i, s := range srcs {
		if err := r.startSource(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s.name(i), err)
		}
		slog.Info("relay source started", "type", s.Type, "listen", s.Listen, "udp", s.UDP, "tcp", s.TCP)
	}
	return nil
}

func (r *Relay) startSource(ctx context.Context, s SourceConfig) error {
	var tlsCfg *tls.Config
	if s.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	switch s.Type {
	case SrcDatadog, SrcHEC:
		tok, err := secret("", s.TokenFile)
		if err != nil {
			return err
		}
		if s.TokenFile != "" && tok == "" {
			return errors.New("token_file is empty")
		}
		h := r.datadogHandler(tok)
		if s.Type == SrcHEC {
			h = r.hecHandler(tok)
		}
		return serveHTTP(ctx, s.Listen, h, tlsCfg)
	case SrcSyslog:
		return r.startSyslog(ctx, s)
	case SrcFluent:
		key, err := secret("", s.SharedKeyFile)
		if err != nil {
			return err
		}
		if s.SharedKeyFile != "" && key == "" {
			return errors.New("shared_key_file is empty")
		}
		return r.startFluent(ctx, s.Listen, key, tlsCfg)
	default:
		return r.startKafka(ctx, s)
	}
}

func listen(addr string, tlsCfg *tls.Config) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil || tlsCfg == nil {
		return lis, err
	}
	return tls.NewListener(lis, tlsCfg), nil
}

func serveHTTP(ctx context.Context, addr string, h http.Handler, tlsCfg *tls.Config) error {
	lis, err := listen(addr, tlsCfg)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("relay source stopped", "listen", addr, "error", err)
		}
	}()
	return nil
}

// logBatcher groups syslog lines into queue writes: a batch goes to the disk write-ahead log as
// soon as it holds batchMax records or batchWait has passed, so at most that window is in memory
// (a queue write fsyncs, so one write per line would be too slow). Forwarding being down never
// loses a record: the queue holds it. Only a failing disk drops a batch (logged).
type logBatcher struct {
	r    *Relay
	mu   sync.Mutex
	recs []*logspb.LogRecord
}

const (
	batchMax  = 500
	batchWait = 100 * time.Millisecond
)

func newLogBatcher(ctx context.Context, r *Relay) *logBatcher {
	b := &logBatcher{r: r}
	go func() {
		t := time.NewTicker(batchWait)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				b.flush()
				return
			case <-t.C:
				b.flush()
			}
		}
	}()
	return b
}

// Gauge and Sum drop: the log-only sources never produce them.
func (b *logBatcher) Gauge(string, string, float64, map[string]string, time.Time) {}
func (b *logBatcher) Sum(string, string, float64, map[string]string, time.Time)   {}

// Log buffers one record (the agent sink.Sink contract).
func (b *logBatcher) Log(severity, body string, attrs map[string]string, at time.Time) {
	b.mu.Lock()
	b.recs = append(b.recs, logRec(severity, body, attrs, at))
	n := len(b.recs)
	b.mu.Unlock()
	if n >= batchMax {
		b.flush()
	}
}

func (b *logBatcher) flush() {
	b.mu.Lock()
	recs := b.recs
	b.recs = nil
	b.mu.Unlock()
	if len(recs) == 0 {
		return
	}
	if err := b.r.logsChunked(recs); err != nil {
		slog.Error("relay syslog: queue write failed, batch dropped", "records", len(recs), "error", err)
	}
}

func logRec(severity, body string, attrs map[string]string, at time.Time) *logspb.LogRecord {
	now := uint64(time.Now().UnixNano()) //nolint:gosec // positive
	var ns uint64
	if !at.IsZero() && at.UnixNano() > 0 {
		ns = uint64(at.UnixNano())
	}
	var kv []*commonpb.KeyValue
	for _, k := range srcconv.SortedKeys(attrs) {
		kv = srcconv.AppendKV(kv, k, srcconv.StrVal(attrs[k]))
	}
	rec := srcconv.LogRecord(ns, now, body, kv)
	if severity != "" {
		srcconv.SetSeverity(rec, severity)
	}
	return rec
}

func logsReq(recs []*logspb.LogRecord) *collogs.ExportLogsServiceRequest {
	req := &collogs.ExportLogsServiceRequest{}
	srcconv.NewScope(req, nil).LogRecords = recs
	return req
}

// logsChunked queues recs, halving a batch the queue calls too large (one WAL record is 8 MiB);
// a single record that is still too large is dropped.
func (r *Relay) logsChunked(recs []*logspb.LogRecord) error {
	err := r.Logs(logsReq(recs))
	if !errors.Is(err, ErrTooLarge) {
		return err
	}
	if len(recs) == 1 {
		slog.Warn("relay source dropped a record larger than the queue limit")
		return nil
	}
	h := len(recs) / 2
	if err := r.logsChunked(recs[:h]); err != nil {
		return err
	}
	return r.logsChunked(recs[h:])
}

// metricList queues metrics under one empty resource.
func (r *Relay) metricList(ms []*metricspb.Metric) error {
	if len(ms) == 0 {
		return nil
	}
	return r.Metrics(&colmetrics.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{}, ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: ms}},
	}}})
}
