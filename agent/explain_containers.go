package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/container"
)

// explainContainers prints the running containers the label filter of the `container` module or
// of `logs.docker` would select. Silent when the module selects by no label (it takes every
// container) or the engine socket is not reachable.
func explainContainers(ctx context.Context, name string, cfg json.RawMessage, w io.Writer) {
	var c struct {
		Labels        container.LabelSet `json:"labels"`
		RequireLabels bool               `json:"require_labels"`
		DockerHost    string             `json:"docker_host"`
		Docker        *struct {
			Labels        container.LabelSet `json:"labels"`
			RequireLabels bool               `json:"require_labels"`
			Host          string             `json:"host"`
		} `json:"docker"`
	}
	if json.Unmarshal(cfg, &c) != nil {
		return
	}
	labels, req, host := c.Labels, c.RequireLabels, c.DockerHost
	if name == "logs" {
		if c.Docker == nil {
			return
		}
		labels, req, host = c.Docker.Labels, c.Docker.RequireLabels, c.Docker.Host
	}
	if p := os.Getenv("WT_AGENT_DOCKER_PROJECT"); p != "" {
		if labels == nil {
			labels = container.LabelSet{}
		}
		labels[container.ComposeProjectLabel] = []string{p}
	}
	if len(labels) == 0 {
		if req {
			fmt.Fprintln(w, "  containers: require_labels is set but no labels are given: none selected")
		}
		return
	}
	if host == "" {
		host = container.DefaultHost()
	}
	d, err := container.NewDocker(host)
	if err != nil {
		return
	}
	d.Labels = labels
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := d.List(lctx)
	if err != nil {
		fmt.Fprintln(w, "  containers: docker engine not reachable, cannot list matches")
		return
	}
	fmt.Fprintf(w, "  containers matching %s: %d", strings.Join(container.LabelFilter(labels), ", "), len(list))
	if len(list) > 0 {
		fmt.Fprintf(w, " (%s)", container.MatchedSummary(list))
	}
	fmt.Fprintln(w)
}
