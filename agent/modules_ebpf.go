package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/custom"
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

func (m ebpfModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	tok, err := m.local.Token()
	if err != nil {
		return err
	}
	go ebpf.Counters.Export(ctx, out.Sum)
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
	var metric ebpftrace.Metric // nil: the exporter cannot send histograms, so no GenAI/MCP metrics
	if h, ok := out.(histogrammer); ok {
		metric = h.Histogram
	}
	return ebpftrace.Run(ctx, cfg, sa.AddSpans, func(name string, v float64, at time.Time) { out.Sum(name, "", v, nil, at) }, metric)
}

// histogrammer is implemented by *OTLP; ebpf_trace's GenAI and MCP metrics need it.
type histogrammer interface {
	Histogram(name, unit string, bounds []float64, counts []uint64, sum float64, count uint64, attrs map[string]string, at time.Time)
}

// ebpfNetModule is `ebpf_net` (INF-038): TCP and DNS telemetry. Off unless enabled locally.
type ebpfNetModule struct{ toggle }

func (ebpfNetModule) Name() string { return "ebpf_net" }

func (ebpfNetModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return ebpfnet.Run(ctx, cfg, out)
}

// pprofModule is `pprof_scrape` (CFT-A15): pull pprof from Go targets. Local config only.
type pprofModule struct {
	toggle
	local *LocalConfig
}

func (pprofModule) Name() string { return "pprof_scrape" }

func (m pprofModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	tok, err := m.local.Token()
	if err != nil {
		return err
	}
	return custom.PprofScrape(ctx, cfg, func(ctx context.Context, service, sampleType string, gz []byte) error {
		p := ebpf.Poster{Endpoint: m.local.Endpoint, Token: tok, Source: "pprof_scrape"}
		return p.Post(ctx, ebpf.Profile{Service: service, Kind: ebpf.Kind(sampleType), Body: gz})
	})
}

// asyncProfilerModule is `async_profiler` (CFT-A15): the operator's asprof on matching JVMs. Local config only.
type asyncProfilerModule struct {
	toggle
	local *LocalConfig
}

func (asyncProfilerModule) Name() string { return "async_profiler" }

func (m asyncProfilerModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	tok, err := m.local.Token()
	if err != nil {
		return err
	}
	return custom.AsyncProfile(ctx, cfg, func(ctx context.Context, service, sampleType string, gz []byte) error {
		p := ebpf.Poster{Endpoint: m.local.Endpoint, Token: tok, Source: "async_profiler"}
		return p.Post(ctx, ebpf.Profile{Service: service, Kind: ebpf.Kind(sampleType), Body: gz})
	})
}
