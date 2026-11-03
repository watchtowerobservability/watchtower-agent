package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/watchtowerobservability/watchtower-agent/agent/cloud"
)

// sfnModule is `aws_stepfunctions` (INF-024): finished Step Functions executions as traces, read
// from the AWS API with the standard credential chain. Off unless the local config enables it;
// remote config can only toggle it and change the interval.
type sfnModule struct{ toggle }

func (sfnModule) Name() string { return "aws_stepfunctions" }

func (sfnModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	sa, ok := out.(spanAdder)
	if !ok {
		return errors.New("aws_stepfunctions: the exporter cannot send spans")
	}
	return cloud.RunStepFunctions(ctx, cfg, out, sa.AddSpans)
}
