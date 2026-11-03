// Package recv holds agent modules matching otelcol receivers Watchtower lacked (CFT-A11):
// `ecs` (awsecscontainermetrics), `file_stats` (filestats) and `s3_otlp` (awss3 receiver).
package recv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// ECSConfig: the task metadata endpoint v4 comes from ECS_CONTAINER_METADATA_URI_V4 (set by the
// ECS agent in every container); Interval defaults to 30s.
type ECSConfig struct {
	Interval string `json:"interval"`
}

type ecsStats struct {
	CPU struct {
		Usage struct {
			Total float64 `json:"total_usage"`
		} `json:"cpu_usage"`
		System float64 `json:"system_cpu_usage"`
		Online float64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	Memory struct {
		Usage float64 `json:"usage"`
		Limit float64 `json:"limit"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		Rx float64 `json:"rx_bytes"`
		Tx float64 `json:"tx_bytes"`
	} `json:"networks"`
}

type ecsTask struct {
	Cluster    string `json:"Cluster"`
	TaskARN    string `json:"TaskARN"`
	Family     string `json:"Family"`
	Revision   string `json:"Revision"`
	Containers []struct {
		DockerID string `json:"DockerId"`
		Name     string `json:"Name"`
	} `json:"Containers"`
}

func interval(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 5*time.Second {
		return 0, errors.New("interval must be a duration of at least 5s")
	}
	return d, nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return errors.New("metadata endpoint unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// RunECS reports per-container CPU, memory and network of the agent's ECS task.
func RunECS(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c ECSConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("ecs: %w", err)
		}
	}
	every, err := interval(c.Interval, 30*time.Second)
	if err != nil {
		return fmt.Errorf("ecs: %w", err)
	}
	base := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if base == "" {
		return errors.New("ecs: ECS_CONTAINER_METADATA_URI_V4 is not set (not running on ECS)")
	}
	hc := &http.Client{Timeout: 10 * time.Second} // link-local task endpoint: netguard would refuse it
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		var task ecsTask
		var stats map[string]ecsStats
		if err := getJSON(ctx, hc, base+"/task", &task); err == nil && getJSON(ctx, hc, base+"/task/stats", &stats) == nil {
			EmitECS(out, task, stats, time.Now())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// EmitECS writes container metrics with aws.ecs.* resource attributes.
func EmitECS(out sink.Sink, task ecsTask, stats map[string]ecsStats, now time.Time) {
	for _, ct := range task.Containers {
		s, ok := stats[ct.DockerID]
		if !ok {
			continue
		}
		a := map[string]string{"aws.ecs.cluster.arn": task.Cluster, "aws.ecs.task.arn": task.TaskARN,
			"aws.ecs.task.family": task.Family, "aws.ecs.task.revision": task.Revision,
			"container.id": ct.DockerID, "container.name": ct.Name}
		out.Sum("container.cpu.time", "ns", s.CPU.Usage.Total, a, now)
		out.Gauge("container.memory.usage", "By", s.Memory.Usage, a, now)
		out.Gauge("container.memory.limit", "By", s.Memory.Limit, a, now)
		for iface, n := range s.Networks {
			na := sink.With(a, "network.interface.name", iface)
			out.Sum("container.network.io", "By", n.Rx, sink.With(na, "network.io.direction", "receive"), now)
			out.Sum("container.network.io", "By", n.Tx, sink.With(na, "network.io.direction", "transmit"), now)
		}
	}
}
