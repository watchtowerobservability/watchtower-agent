package main

// Forwarding a copy to third-party backends (CFT-A10, outbound auth CFT-A17). The agent keeps
// exporting to the gateway; each `forward:` entry of the agent's own config file (never remote
// config: it names where data leaves) also gets every OTLP batch it subscribes to: kind
// "otlp_http" posts the same protobuf to <endpoint>/v1/<signal>; kind "kafka" produces it to a
// topic (otlp_proto encoding, the OTel Kafka exporter's default). Copies are best effort: a
// bounded queue, dropped (and counted in the log) when the backend is slow or down, so a
// third-party outage can never stall or grow the primary path. Header and password values may
// be secret references (`${vault:...}`, see secretref.go). More sinks and oauth2, sigv4 and google
// auth are in forward_sinks.go.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
)

// ForwardTarget is one extra destination.
type ForwardTarget struct {
	Kind     string            `yaml:"kind"`     // otlp_http, kafka, splunkhec, datadog, googlecloud, syslog, s3 or loadbalancing (forward_sinks.go)
	Endpoint string            `yaml:"endpoint"` // otlp_http base URL (https://otlp.example.com:4318)
	Signals  []string          `yaml:"signals"`  // metrics, logs, traces (default all)
	Headers  map[string]string `yaml:"headers"`  // e.g. api keys
	Bearer   string            `yaml:"bearer_token"`
	Basic    *struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"basic_auth"`
	OAuth2    *ForwardOAuth2 `yaml:"oauth2"`     // client credentials, cached until expiry
	SigV4     *ForwardSigV4  `yaml:"sigv4"`      // AWS default credential chain, optionally assuming role_arn
	Proxy     string         `yaml:"http_proxy"` // http(s) proxy for this target (forward_proxy.go)
	NoProxy   []string       `yaml:"no_proxy"`   // hosts and domains that bypass Proxy
	Google    bool           `yaml:"google"`     // token from the GCE metadata server
	Token     string         `yaml:"token"`      // splunkhec and datadog
	Project   string         `yaml:"project"`    // googlecloud
	Bucket    string         `yaml:"bucket"`     // s3 (with sigv4; endpoint overrides the AWS host)
	Endpoints []string       `yaml:"endpoints"`  // loadbalancing
	// kafka
	Brokers []string `yaml:"brokers"`
	Topic   string   `yaml:"topic"` // default otlp_<signal>
	TLS     bool     `yaml:"tls"`
	SASL    *struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"sasl_plain"`
}

const forwardQueue = 256

type fwdItem struct {
	signal string
	body   []byte
}

type forwarder struct {
	t       ForwardTarget
	q       chan fwdItem
	hc      *http.Client
	kafka   *kgo.Client
	hdr     http.Header
	aws     awsCreds // sigv4 credentials, loaded once per target
	dropped atomic.Int64
	bearer  cachedToken
	google  bool
	next    uint32
}

func (f *forwarder) wants(signal string) bool {
	return len(f.t.Signals) == 0 || slices.Contains(f.t.Signals, signal)
}

// resolveRef turns one `${provider:ref}` value into its secret; plain values pass through.
func resolveRef(ctx context.Context, v string) (string, error) {
	m := secretRefRe.FindStringSubmatch(v)
	if m == nil {
		return v, nil
	}
	s, err := defaultResolver.value(ctx, m[1], m[2])
	if err != nil {
		return "", fmt.Errorf("forward: secret reference %s: %w", m[1], err)
	}
	return strings.Replace(v, m[0], s, 1), nil
}

func newForwarder(ctx context.Context, t ForwardTarget) (*forwarder, error) {
	f := &forwarder{t: t, q: make(chan fwdItem, forwardQueue), hdr: http.Header{}}
	for _, s := range t.Signals {
		if s != "metrics" && s != "logs" && s != "traces" {
			return nil, fmt.Errorf("forward: unknown signal %q", s)
		}
	}
	switch t.Kind {
	case "otlp_http":
		u, err := url.Parse(t.Endpoint)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, errors.New("forward: otlp_http endpoint must be an http(s) URL")
		}
		for k, v := range t.Headers {
			rv, err := resolveRef(ctx, v)
			if err != nil {
				return nil, err
			}
			f.hdr.Set(k, rv)
		}
		if t.Bearer != "" {
			tok, err := resolveRef(ctx, t.Bearer)
			if err != nil {
				return nil, err
			}
			f.hdr.Set("Authorization", "Bearer "+tok)
		}
		if t.Basic != nil {
			pw, err := resolveRef(ctx, t.Basic.Password)
			if err != nil {
				return nil, err
			}
			f.hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(t.Basic.Username+":"+pw)))
		}
		hc, err := forwardClient(ctx, t)
		if err != nil {
			return nil, err
		}
		f.hc = hc
		f.google = t.Google
		if err := f.initAuth(); err != nil {
			return nil, err
		}
	case "kafka":
		if len(t.Brokers) == 0 {
			return nil, errors.New("forward: kafka brokers required")
		}
		opts := []kgo.Opt{kgo.SeedBrokers(t.Brokers...), kgo.ProducerBatchMaxBytes(maxBodyBytes + 1<<16), kgo.MaxBufferedRecords(forwardQueue)}
		if t.TLS {
			opts = append(opts, kgo.DialTLS())
		}
		if t.SASL != nil {
			pw, err := resolveRef(ctx, t.SASL.Password)
			if err != nil {
				return nil, err
			}
			opts = append(opts, kgo.SASL(plain.Auth{User: t.SASL.Username, Pass: pw}.AsMechanism()))
		}
		cl, err := kgo.NewClient(opts...)
		if err != nil {
			return nil, errors.New("forward: kafka client")
		}
		f.kafka = cl
	default:
		if err := f.initSink(ctx); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *forwarder) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			if f.kafka != nil {
				f.kafka.Close()
			}
			return
		case it := <-f.q:
			if err := f.send(ctx, it); err != nil {
				n := f.dropped.Add(1)
				if n == 1 || n%100 == 0 {
					slog.Warn("forward copy dropped", "kind", f.t.Kind, "signal", it.signal, "dropped_total", n, "error", err)
				}
			}
		}
	}
}

func (f *forwarder) send(ctx context.Context, it fwdItem) error {
	if f.kafka != nil {
		topic := f.t.Topic
		if topic == "" {
			topic = "otlp_" + it.signal
		}
		ctx, cancel := context.WithTimeout(ctx, exportTimeout)
		defer cancel()
		return f.kafka.ProduceSync(ctx, &kgo.Record{Topic: topic, Value: it.body}).FirstErr()
	}
	if f.t.Kind != "otlp_http" {
		return f.sendSink(ctx, it)
	}
	return f.do(ctx, http.MethodPost, strings.TrimSuffix(f.t.Endpoint, "/")+"/v1/"+it.signal, "application/x-protobuf", it.body)
}

// Forwarders is the tee the exporter calls with every marshalled batch.
type Forwarders []*forwarder

// StartForwarders validates the targets and starts one sender each.
func StartForwarders(ctx context.Context, ts []ForwardTarget) (Forwarders, error) {
	var out Forwarders
	for _, t := range ts {
		f, err := newForwarder(ctx, t)
		if err != nil {
			return nil, err
		}
		go f.run(ctx)
		out = append(out, f)
	}
	return out, nil
}

// Tee queues a copy of an export body (path /v1/metrics, /v1/logs or /v1/traces) without blocking.
func (fs Forwarders) Tee(path string, body []byte) {
	signal := strings.TrimPrefix(path, "/v1/")
	for _, f := range fs {
		if !f.wants(signal) {
			continue
		}
		select {
		case f.q <- fwdItem{signal, body}:
		default:
			f.dropped.Add(1)
		}
	}
}
