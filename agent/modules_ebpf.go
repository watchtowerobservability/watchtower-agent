package main

import (
	"context"
	"encoding/json"
	"errors"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/ebpf"
	ebpfnet "github.com/watchtowerobservability/watchtower-agent/agent/ebpf/net"
	ebpftrace "github.com/watchtowerobservability/watchtower-agent/agent/ebpf/trace"
)

// ebpfModule is `ebpf_profiler`: off unless the local config defines it with enabled: true.
// Remote config can only toggle it and change the interval (the toggle overlay).
type ebpfModule struct {
	toggle
	local *LocalConfig
}

func (ebpfModule) Name() string { return "ebpf_profiler" }

func (m ebpfModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	tok, err := m.local.Token()
	if err != nil {
		return err
	}
	return ebpf.Run(ctx, cfg, m.local.Endpoint, tok)
}

// spanAdder is implemented by *OTLP; ebpf_trace needs it to ship spans.
type spanAdder interface {
	AddSpans(res map[string]string, spans []*tracepb.Span)
}

// ebpfTraceModule is `ebpf_trace` (APM-010, TRC-020): zero-code request spans. Off unless the
// local config enables it; remote config can only toggle it.
type ebpfTraceModule struct{ toggle }

func (ebpfTraceModule) Name() string { return "ebpf_trace" }

func (ebpfTraceModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	sa, ok := out.(spanAdder)
	if !ok {
		return errors.New("ebpf_trace: the exporter cannot send spans")
	}
	return ebpftrace.Run(ctx, cfg, sa.AddSpans)
}

// ebpfNetModule is `ebpf_net` (INF-038): TCP and DNS telemetry. Off unless enabled locally.
type ebpfNetModule struct{ toggle }

func (ebpfNetModule) Name() string { return "ebpf_net" }

func (ebpfNetModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return ebpfnet.Run(ctx, cfg, out)
}
