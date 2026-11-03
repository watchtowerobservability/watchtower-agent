package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	dto "github.com/prometheus/client_model/go"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// The kubelet's /stats/summary document, reduced to the fields the agent reports. Numbers are
// pointers because the kubelet omits what it cannot measure.
type (
	CPUStats struct {
		UsageNanoCores       *uint64 `json:"usageNanoCores"`
		UsageCoreNanoSeconds *uint64 `json:"usageCoreNanoSeconds"`
	}
	MemStats struct {
		UsageBytes      *uint64 `json:"usageBytes"`
		WorkingSetBytes *uint64 `json:"workingSetBytes"`
		AvailableBytes  *uint64 `json:"availableBytes"`
	}
	FSStats struct {
		UsedBytes     *uint64 `json:"usedBytes"`
		CapacityBytes *uint64 `json:"capacityBytes"`
	}
	NetIface struct {
		Name     string  `json:"name"`
		RxBytes  *uint64 `json:"rxBytes"`
		RxErrors *uint64 `json:"rxErrors"`
		TxBytes  *uint64 `json:"txBytes"`
		TxErrors *uint64 `json:"txErrors"`
	}
	NetStats struct {
		Interfaces []NetIface `json:"interfaces"`
	}
	ContainerStats struct {
		Name   string    `json:"name"`
		CPU    *CPUStats `json:"cpu"`
		Memory *MemStats `json:"memory"`
		Rootfs *FSStats  `json:"rootfs"`
	}
	PodRef struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	}
	PodStats struct {
		PodRef     PodRef           `json:"podRef"`
		CPU        *CPUStats        `json:"cpu"`
		Memory     *MemStats        `json:"memory"`
		Network    *NetStats        `json:"network"`
		Ephemeral  *FSStats         `json:"ephemeral-storage"`
		Containers []ContainerStats `json:"containers"`
	}
	NodeStats struct {
		NodeName string    `json:"nodeName"`
		CPU      *CPUStats `json:"cpu"`
		Memory   *MemStats `json:"memory"`
		Network  *NetStats `json:"network"`
		FS       *FSStats  `json:"fs"`
	}
	// Summary is the response of GET /stats/summary.
	Summary struct {
		Node NodeStats  `json:"node"`
		Pods []PodStats `json:"pods"`
	}
)

const maxSummaryBytes = 64 << 20

// ParseSummary decodes a /stats/summary body (bounded to 64 MiB).
func ParseSummary(r io.Reader) (*Summary, error) {
	var s Summary
	if err := json.NewDecoder(io.LimitReader(r, maxSummaryBytes)).Decode(&s); err != nil {
		return nil, fmt.Errorf("kubelet summary: %w", err)
	}
	return &s, nil
}

// Kubelet fetches the summary of one node's kubelet with the pod's service account token
// (RBAC: get on nodes/stats).
type Kubelet struct {
	URL       string // https://<node ip>:10250
	TokenFile string
	client    *http.Client
}

// NewKubelet builds the client. The kubelet's serving certificate is usually signed by a CA the
// cluster CA file does not cover, so verification uses caFile when given and is skipped only
// when insecure is set in the agent's own config (it is never settable remotely).
func NewKubelet(url, tokenFile, caFile string, insecure bool) (*Kubelet, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in, local config only
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates", caFile)
		}
		tc.RootCAs = pool
	}
	hc := netguard.NewClientWith(netguard.FromEnv("agent"), netguard.Options{}, func(tr *http.Transport) { tr.TLSClientConfig = tc })
	hc.Timeout = 15 * time.Second
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Kubelet{URL: strings.TrimRight(url, "/"), TokenFile: tokenFile, client: hc}, nil
}

// get fetches one kubelet path. The token file is read on every call because projected tokens
// rotate.
func (k *Kubelet) get(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.URL+path, nil)
	if err != nil {
		return nil, err
	}
	if k.TokenFile != "" {
		tok, err := os.ReadFile(k.TokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("kubelet %s: status %d", path, resp.StatusCode)
	}
	return resp.Body, nil
}

// Summary fetches and parses /stats/summary.
func (k *Kubelet) Summary(ctx context.Context) (*Summary, error) {
	body, err := k.get(ctx, "/stats/summary")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return ParseSummary(body)
}

// Cadvisor fetches and parses /metrics/cadvisor (RBAC: get on nodes/metrics).
func (k *Kubelet) Cadvisor(ctx context.Context) (map[string]*dto.MetricFamily, error) {
	body, err := k.get(ctx, "/metrics/cadvisor")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return parseProm(io.LimitReader(body, maxPromBody))
}

func gauge(out sink.Sink, name, unit string, v *uint64, scale float64, a map[string]string, at time.Time) {
	if v != nil {
		out.Gauge(name, unit, float64(*v)/scale, a, at)
	}
}

func counter(out sink.Sink, name, unit string, v *uint64, scale float64, a map[string]string, at time.Time) {
	if v != nil {
		out.Sum(name, unit, float64(*v)/scale, a, at)
	}
}

func emitCPU(out sink.Sink, p string, c *CPUStats, a map[string]string, at time.Time) {
	if c != nil {
		gauge(out, p+".cpu.usage", "{cpu}", c.UsageNanoCores, 1e9, a, at)
		counter(out, p+".cpu.time", "s", c.UsageCoreNanoSeconds, 1e9, a, at)
	}
}

func emitMem(out sink.Sink, p string, m *MemStats, a map[string]string, at time.Time) {
	if m != nil {
		gauge(out, p+".memory.usage", "By", m.UsageBytes, 1, a, at)
		gauge(out, p+".memory.working_set", "By", m.WorkingSetBytes, 1, a, at)
		gauge(out, p+".memory.available", "By", m.AvailableBytes, 1, a, at)
	}
}

func emitNet(out sink.Sink, p string, n *NetStats, a map[string]string, at time.Time) {
	if n == nil {
		return
	}
	for _, i := range n.Interfaces {
		rx := sink.With(a, "network.interface.name", i.Name, "network.io.direction", "receive")
		tx := sink.With(a, "network.interface.name", i.Name, "network.io.direction", "transmit")
		counter(out, p+".network.io", "By", i.RxBytes, 1, rx, at)
		counter(out, p+".network.io", "By", i.TxBytes, 1, tx, at)
		counter(out, p+".network.errors", "{error}", i.RxErrors, 1, rx, at)
		counter(out, p+".network.errors", "{error}", i.TxErrors, 1, tx, at)
	}
}

// Emit turns a summary into k8s.node.*, k8s.pod.* and k8s.container.* usage metrics. podRes gives
// the resource attributes of a pod (enrichment); nodeRes those of the node. Container names are
// point attributes; everything about the owning object is on the resource.
//
// The pod uid and, when podRes names it, the workload uid (k8s.parent.id) are also point
// attributes: series labels keep only point attributes, and the explorer joins usage to pods and
// sums it per workload by them (INF-009). k8s.parent.id stays off the resource, where only the
// cluster agent names a parent.
func Emit(out sink.Sink, s *Summary, nodeRes map[string]string, podRes func(PodRef) map[string]string, at time.Time) {
	na := sink.Res(nodeRes)
	emitCPU(out, "k8s.node", s.Node.CPU, na, at)
	emitMem(out, "k8s.node", s.Node.Memory, na, at)
	emitNet(out, "k8s.node", s.Node.Network, na, at)
	if f := s.Node.FS; f != nil {
		gauge(out, "k8s.node.filesystem.usage", "By", f.UsedBytes, 1, na, at)
		gauge(out, "k8s.node.filesystem.capacity", "By", f.CapacityBytes, 1, na, at)
	}
	for _, p := range s.Pods {
		pa := map[string]string{"k8s.pod.uid": p.PodRef.UID}
		for k, v := range podRes(p.PodRef) {
			if k == "k8s.parent.id" {
				pa[k] = v
			} else {
				pa[sink.ResourcePrefix+k] = v
			}
		}
		emitCPU(out, "k8s.pod", p.CPU, pa, at)
		emitMem(out, "k8s.pod", p.Memory, pa, at)
		emitNet(out, "k8s.pod", p.Network, pa, at)
		if p.Ephemeral != nil {
			gauge(out, "k8s.pod.filesystem.usage", "By", p.Ephemeral.UsedBytes, 1, pa, at)
		}
		for _, c := range p.Containers {
			ca := sink.With(pa, "k8s.container.name", c.Name)
			emitCPU(out, "k8s.container", c.CPU, ca, at)
			emitMem(out, "k8s.container", c.Memory, ca, at)
			if c.Rootfs != nil {
				gauge(out, "k8s.container.filesystem.usage", "By", c.Rootfs.UsedBytes, 1, ca, at)
			}
		}
	}
}
