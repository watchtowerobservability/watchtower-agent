// Package relay is `wt-agent --mode relay`: a store-and-forward OTLP relay for networks that
// cannot reach the gateway all the time. It accepts OTLP gRPC and HTTP, applies the edge-safe
// processors (redact, filter, sample, enrich), queues batches in a disk write-ahead log and
// forwards them to the gateway with the project's ingestion key. Relays of one peer group shard
// traces by trace id so the spans of a trace reach the gateway through one relay.
package relay

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"
)

const (
	maxBody       = 32 << 20
	heartbeatTick = 30 * time.Second
	// Version is reported in heartbeats.
	Version = "relay-1"
)

// Relay wires the receivers, processors, queue, peers and forwarder together.
type Relay struct {
	Proc        *Processors
	Q           *Queue
	Peers       *Peers // nil = no peer group
	Fwd         *Forwarder
	AcceptToken string
	poke        chan struct{}
}

func newClient() *http.Client {
	c := netguard.NewClientWith(netguard.Policy{AllowPrivate: true, Purpose: "agent"}, netguard.Options{Family: netguard.DefaultFamily},
		func(tr *http.Transport) { tr.ResponseHeaderTimeout = 30 * time.Second })
	c.Timeout = time.Minute
	return c
}

// Run starts the relay from a config file and blocks until ctx ends.
func Run(ctx context.Context, cfgPath string) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	key, err := secret("WT_RELAY_KEY", cfg.KeyFile)
	if err != nil || key == "" {
		return fmt.Errorf("relay: ingestion key missing (WT_RELAY_KEY or key_file): %v", err)
	}
	accept, err := secret("WT_RELAY_ACCEPT_TOKEN", cfg.AcceptTokenFile)
	if err != nil {
		return err
	}
	proc, err := Compile(cfg.Processors)
	if err != nil {
		return err
	}
	q, err := OpenQueue(cfg.Queue.Dir, cfg.Queue.MaxBytes)
	if err != nil {
		return fmt.Errorf("relay queue: %w", err)
	}
	defer q.Close()
	client := newClient()
	r := &Relay{Proc: proc, Q: q, AcceptToken: accept, poke: make(chan struct{}, 1),
		Fwd: &Forwarder{Q: q, Upstream: cfg.Upstream, Key: key, HTTP: client}}
	if cfg.Self != "" || len(cfg.Peers) > 0 || cfg.PeersFile != "" {
		ps, err := secret("WT_RELAY_PEER_SECRET", cfg.PeerSecretFile)
		if err != nil {
			return err
		}
		r.Peers = NewPeers(cfg.Self, ps, cfg.Peers)
		r.Peers.File, r.Peers.HTTP = cfg.PeersFile, client
		if err := r.Peers.Refresh(); err != nil {
			slog.Warn("relay peers file", "error", err)
		}
		go every(ctx, heartbeatTick, func() {
			if err := r.Peers.Refresh(); err != nil {
				slog.Warn("relay peers file", "error", err)
			}
		})
	}
	token, err := secret("WT_RELAY_TOKEN", cfg.TokenFile)
	if err != nil {
		return err
	}
	if cfg.API != "" && token != "" {
		go every(ctx, heartbeatTick, func() { r.heartbeat(ctx, client, cfg.API, token) })
	}
	go r.Fwd.Run(ctx, r.poke)

	hs := &http.Server{Addr: cfg.ListenHTTP, Handler: r.Handler(), ReadHeaderTimeout: 10 * time.Second}
	lis, err := net.Listen("tcp", cfg.ListenGRPC)
	if err != nil {
		return err
	}
	gs := r.GRPC()
	errc := make(chan error, 2)
	go func() { errc <- hs.ListenAndServe() }()
	go func() { errc <- gs.Serve(lis) }()
	slog.Info("wt-agent relay started", "http", cfg.ListenHTTP, "grpc", cfg.ListenGRPC, "upstream", cfg.Upstream)
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(sc)
	gs.GracefulStop()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

func every(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

func (r *Relay) heartbeat(ctx context.Context, c *http.Client, api, token string) {
	body, _ := json.Marshal(map[string]any{"queue_depth": r.Q.Depth(), "dropped_total": r.Q.Dropped(), "version": Version})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/v1/relays/heartbeat", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		slog.Warn("relay heartbeat failed", "error", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		slog.Warn("relay heartbeat rejected", "status", resp.StatusCode)
	}
}

// --- ingest -------------------------------------------------------------------------------

// Logs processes and queues a log batch.
func (r *Relay) Logs(req *collogs.ExportLogsServiceRequest) error {
	if r.Proc.Logs(req) == 0 {
		return nil
	}
	return r.enqueue("/v1/logs", req)
}

// Traces processes and queues a trace batch. Unless the batch came from a peer, spans owned by
// another relay of the group are sent there; if that fails the span stays here (never lost).
func (r *Relay) Traces(ctx context.Context, req *coltrace.ExportTraceServiceRequest, fromPeer bool) error {
	if fromPeer || r.Peers == nil || !r.Peers.Active() {
		return r.localTraces(req)
	}
	var first error
	for owner, part := range SplitTraces(req, r.Peers.Owner) {
		if owner != r.Peers.Self {
			if err := r.Peers.Send(ctx, owner, part); err == nil {
				continue
			} else {
				slog.Warn("relay peer unreachable, keeping spans locally", "peer", owner, "error", err)
			}
		}
		if err := r.localTraces(part); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *Relay) localTraces(req *coltrace.ExportTraceServiceRequest) error {
	if r.Proc.Traces(req) == 0 {
		return nil
	}
	return r.enqueue("/v1/traces", req)
}

// Metrics are queued unchanged: the processors apply to logs and spans.
func (r *Relay) Metrics(req *colmetrics.ExportMetricsServiceRequest) error {
	return r.enqueue("/v1/metrics", req)
}

func (r *Relay) enqueue(path string, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	if err := r.Q.Add(path, b); err != nil {
		return err
	}
	select {
	case r.poke <- struct{}{}:
	default:
	}
	return nil
}

func (r *Relay) allowed(got string) bool {
	return r.AcceptToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+r.AcceptToken)) == 1
}

// --- OTLP/HTTP ----------------------------------------------------------------------------

// Handler serves OTLP/HTTP (`/v1/logs`, `/v1/traces`, `/v1/metrics`, protobuf or JSON, optional
// gzip), `/healthz` and `/metrics`.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /metrics", r.metrics)
	mux.HandleFunc("POST /v1/logs", r.http(func(_ *http.Request, b []byte, un func([]byte, proto.Message) error) error {
		req := &collogs.ExportLogsServiceRequest{}
		if err := un(b, req); err != nil {
			return err
		}
		return r.Logs(req)
	}, &collogs.ExportLogsServiceResponse{}))
	mux.HandleFunc("POST /v1/traces", r.http(func(hr *http.Request, b []byte, un func([]byte, proto.Message) error) error {
		req := &coltrace.ExportTraceServiceRequest{}
		if err := un(b, req); err != nil {
			return err
		}
		peer := r.Peers != nil && r.Peers.Authentic(hr.Header.Get(PeerHeader))
		return r.Traces(hr.Context(), req, peer)
	}, &coltrace.ExportTraceServiceResponse{}))
	mux.HandleFunc("POST /v1/metrics", r.http(func(_ *http.Request, b []byte, un func([]byte, proto.Message) error) error {
		req := &colmetrics.ExportMetricsServiceRequest{}
		if err := un(b, req); err != nil {
			return err
		}
		return r.Metrics(req)
	}, &colmetrics.ExportMetricsServiceResponse{}))
	return mux
}

type badRequest struct{ error }

func (r *Relay) http(h func(*http.Request, []byte, func([]byte, proto.Message) error) error, resp proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, hr *http.Request) {
		if !r.allowed(hr.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body io.Reader = http.MaxBytesReader(w, hr.Body, maxBody)
		if hr.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(body)
			if err != nil {
				http.Error(w, "bad gzip", http.StatusBadRequest)
				return
			}
			body = io.LimitReader(gz, maxBody+1)
		}
		raw, err := io.ReadAll(body)
		if err != nil || len(raw) > maxBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ct := hr.Header.Get("Content-Type")
		isJSON := strings.HasPrefix(ct, "application/json")
		un := func(b []byte, m proto.Message) error {
			var err error
			if isJSON {
				err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, m)
			} else {
				err = proto.Unmarshal(b, m)
			}
			if err != nil {
				return badRequest{err}
			}
			return nil
		}
		if err := h(hr, raw, un); err != nil {
			switch {
			case errors.As(err, &badRequest{}):
				http.Error(w, "invalid OTLP payload", http.StatusBadRequest)
			case errors.Is(err, ErrTooLarge):
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			default:
				slog.Error("relay enqueue failed", "error", err)
				w.Header().Set("Retry-After", "5")
				http.Error(w, "queue unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		var out []byte
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			out, _ = protojson.Marshal(resp)
		} else {
			w.Header().Set("Content-Type", "application/x-protobuf")
			out, _ = proto.Marshal(resp)
		}
		_, _ = w.Write(out)
	}
}

func (r *Relay) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE wt_relay_queue_depth gauge\nwt_relay_queue_depth %d\n", r.Q.Depth())
	fmt.Fprintf(w, "# TYPE wt_relay_dropped_total counter\nwt_relay_dropped_total %d\n", r.Q.Dropped())
	fmt.Fprintf(w, "# TYPE wt_relay_forwarded_total counter\nwt_relay_forwarded_total %d\n", r.Fwd.Forwarded.Load())
	fmt.Fprintf(w, "# TYPE wt_relay_rejected_total counter\nwt_relay_rejected_total %d\n", r.Fwd.Rejected.Load())
}

// --- OTLP/gRPC ----------------------------------------------------------------------------

type logsSvc struct {
	collogs.UnimplementedLogsServiceServer
	r *Relay
}

func (s logsSvc) Export(_ context.Context, req *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	return &collogs.ExportLogsServiceResponse{}, grpcErr(s.r.Logs(req))
}

type traceSvc struct {
	coltrace.UnimplementedTraceServiceServer
	r *Relay
}

func (s traceSvc) Export(ctx context.Context, req *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	return &coltrace.ExportTraceServiceResponse{}, grpcErr(s.r.Traces(ctx, req, false))
}

type metricsSvc struct {
	colmetrics.UnimplementedMetricsServiceServer
	r *Relay
}

func (s metricsSvc) Export(_ context.Context, req *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	return &colmetrics.ExportMetricsServiceResponse{}, grpcErr(s.r.Metrics(req))
}

func grpcErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTooLarge):
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	return status.Error(codes.Unavailable, "queue unavailable")
}

// GRPC returns the OTLP/gRPC server (not yet serving).
func (r *Relay) GRPC() *grpc.Server {
	auth := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		got := ""
		if v := md.Get("authorization"); len(v) > 0 {
			got = v[0]
		}
		if !r.allowed(got) {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}
		return h(ctx, req)
	}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(maxBody), grpc.UnaryInterceptor(auth))
	collogs.RegisterLogsServiceServer(srv, logsSvc{r: r})
	coltrace.RegisterTraceServiceServer(srv, traceSvc{r: r})
	colmetrics.RegisterMetricsServiceServer(srv, metricsSvc{r: r})
	return srv
}
