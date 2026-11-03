package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/watchtowerobservability/watchtower-agent/agent/custom"
	"github.com/watchtowerobservability/watchtower-agent/agent/recv"
)

// agentEnricher is shared by the enrich module (which loads its rules) and the exporter.
var agentEnricher = &custom.Enricher{}

// enrichModule is `enrich` (CFT-A06): discovery labels joined into all data. Local config only.
type enrichModule struct{ toggle }

func (enrichModule) Name() string { return "enrich" }
func (enrichModule) Start(ctx context.Context, cfg json.RawMessage, _ Exporter) error {
	return agentEnricher.Run(ctx, cfg)
}

// Receiver modules of CFT-A11. All are off unless the local config enables them; remote config
// can only toggle them.

type ecsModule struct{ toggle }

func (ecsModule) Name() string { return "ecs" }
func (ecsModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return recv.RunECS(ctx, cfg, out)
}

type fileStatsModule struct{ toggle }

func (fileStatsModule) Name() string { return "file_stats" }
func (fileStatsModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return recv.RunFileStats(ctx, cfg, out)
}

type s3Module struct {
	toggle
	stateDir string
}

// rawSender is implemented by *OTLP (and passed through by the tap wrapper).
type rawSender interface {
	SendRaw(ctx context.Context, path string, body []byte) error
}

func (s3Module) Name() string { return "s3_otlp" }
func (m s3Module) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	rs, ok := out.(rawSender)
	if !ok {
		return errors.New("s3_otlp: the exporter cannot send raw OTLP")
	}
	return recv.RunS3(ctx, cfg, m.stateDir, rs.SendRaw)
}

// SendRaw posts an OTLP protobuf body as is (copied to forwarders like every batch).
func (o *OTLP) SendRaw(ctx context.Context, path string, body []byte) error {
	if o.Tee != nil {
		o.Tee(path, body)
	}
	_, err := o.send(ctx, path, body)
	return err
}

func (e *tapExporter) SendRaw(ctx context.Context, path string, body []byte) error {
	if rs, ok := e.Exporter.(rawSender); ok {
		return rs.SendRaw(ctx, path, body)
	}
	return errors.New("exporter cannot send raw OTLP")
}
