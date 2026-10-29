package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/aiserving"
	"github.com/watchtowerobservability/watchtower-agent/agent/cloud"
	"github.com/watchtowerobservability/watchtower-agent/agent/container"
	"github.com/watchtowerobservability/watchtower-agent/agent/gpu"
	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/hw"
	"github.com/watchtowerobservability/watchtower-agent/agent/k8s"
	"github.com/watchtowerobservability/watchtower-agent/agent/logs"
	"github.com/watchtowerobservability/watchtower-agent/agent/netconf"
	"github.com/watchtowerobservability/watchtower-agent/agent/netflow"
	"github.com/watchtowerobservability/watchtower-agent/agent/netpath"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
	"github.com/watchtowerobservability/watchtower-agent/agent/snmp"
	"github.com/watchtowerobservability/watchtower-agent/agent/virt"
)

// toggle is all that remote config may say about the infrastructure modules: switch one on or
// off and change its interval. Paths, sockets, tool locations and listen addresses exist only
// in the agent's own file.
type toggle struct {
	// emptyOK lets the remote tune a module the local file does not mention (host runs by
	// default; the others need local settings to do anything).
	emptyOK bool
}

func (t toggle) Overlay(local, remote json.RawMessage) (json.RawMessage, error) {
	if len(local) == 0 {
		if !t.emptyOK {
			return nil, errors.New("the module is not defined in the agent's own config")
		}
		local = json.RawMessage(`{}`)
	}
	var r struct {
		Enabled  *bool  `json:"enabled"`
		Interval string `json:"interval"`
	}
	dec := json.NewDecoder(bytes.NewReader(remote))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("remote config may only set enabled and interval: %w", err)
	}
	if r.Interval != "" {
		if d, err := time.ParseDuration(r.Interval); err != nil || d <= 0 {
			return nil, fmt.Errorf("interval %q is not a duration", r.Interval)
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(local, &m); err != nil {
		return nil, err
	}
	if r.Enabled != nil {
		m["enabled"], _ = json.Marshal(*r.Enabled)
	}
	if r.Interval != "" {
		m["interval"], _ = json.Marshal(r.Interval)
	}
	return json.Marshal(m)
}

type hostModule struct{ toggle }

func (hostModule) Name() string { return "host" }
func (hostModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return host.Run(ctx, cfg, out)
}

type containerModule struct{ toggle }

func (containerModule) Name() string { return "container" }
func (containerModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return container.Run(ctx, cfg, out)
}

type aiServingModule struct{ toggle }

func (aiServingModule) Name() string { return "aiserving" }
func (aiServingModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return aiserving.Run(ctx, cfg, out)
}

type gpuModule struct{ toggle }

func (gpuModule) Name() string { return "gpu" }
func (gpuModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return gpu.Run(ctx, cfg, out)
}

type logsModule struct {
	toggle
	stateDir string
}

func (logsModule) Name() string { return "logs" }
func (m logsModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return logs.Run(ctx, cfg, m.stateDir, out)
}

type k8sClusterModule struct{ toggle }

func (k8sClusterModule) Name() string { return "k8s_cluster" }
func (k8sClusterModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return k8s.RunCluster(ctx, cfg, out)
}

type k8sNodeModule struct {
	toggle
	stateDir string
}

func (k8sNodeModule) Name() string { return "k8s_node" }
func (m k8sNodeModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return k8s.RunNode(ctx, cfg, m.stateDir, out)
}

type flowsModule struct{ toggle }

func (flowsModule) Name() string { return "flows" }
func (flowsModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return netflow.Run(ctx, cfg, out)
}

type pathModule struct{ toggle }

func (pathModule) Name() string { return "path" }
func (pathModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return netpath.Run(ctx, cfg, out)
}

type topologyModule struct{ toggle }

func (topologyModule) Name() string { return "topology" }
func (topologyModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return snmp.RunTopology(ctx, cfg, out)
}

type awsModule struct{ toggle }

func (awsModule) Name() string { return "aws" }
func (awsModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return cloud.RunAWS(ctx, cfg, out)
}

type cloudPullModule struct{ toggle }

func (cloudPullModule) Name() string { return "cloud_pull" }
func (cloudPullModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return cloud.RunPulls(ctx, cfg, out)
}

type azureEventHubModule struct{ toggle }

func (azureEventHubModule) Name() string { return "azure_eventhub" }
func (azureEventHubModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return cloud.RunEventHub(ctx, cfg, out)
}

type proxmoxModule struct{ toggle }

func (proxmoxModule) Name() string { return "proxmox" }
func (proxmoxModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return virt.RunProxmox(ctx, cfg, out)
}

type nutanixModule struct{ toggle }

func (nutanixModule) Name() string { return "nutanix" }
func (nutanixModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return virt.RunNutanix(ctx, cfg, out)
}

type openstackModule struct{ toggle }

func (openstackModule) Name() string { return "openstack" }
func (openstackModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return virt.RunOpenStack(ctx, cfg, out)
}

type libvirtModule struct{ toggle }

func (libvirtModule) Name() string { return "libvirt" }
func (libvirtModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return virt.RunLibvirt(ctx, cfg, out)
}

type vsphereModule struct{ toggle }

func (vsphereModule) Name() string { return "vsphere" }
func (vsphereModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return virt.RunVSphere(ctx, cfg, out)
}

// integrationModule wraps a database, queue or service collector from the integrations
// package. Its address, DSN and credentials exist only in the agent's own file, so remote
// config can only toggle it.
type integrationModule struct {
	toggle
	name string
	run  func(context.Context, json.RawMessage, sink.Sink) error
}

func (m integrationModule) Name() string { return m.name }
func (m integrationModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return m.run(ctx, cfg, out)
}

type hwModule struct{ toggle }

func (hwModule) Name() string { return "hw" }
func (hwModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return hw.Run(ctx, cfg, out)
}

type snmpModule struct{ toggle }

func (snmpModule) Name() string { return "snmp" }
func (snmpModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return snmp.Run(ctx, cfg, out)
}

type netconfModule struct{ toggle }

func (netconfModule) Name() string { return "netconf" }
func (netconfModule) Start(ctx context.Context, cfg json.RawMessage, out Exporter) error {
	return netconf.Run(ctx, cfg, out)
}
