// Package gpu reads GPU metrics from the vendor command-line tools at locally configured paths.
//
// shortcut: NVML is not loaded dynamically; nvidia-smi is run instead (one process per poll).
// Upgrade to a purego NVML binding if a poll every few seconds proves too heavy.
package gpu

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// NvidiaQuery is the fixed argument list for nvidia-smi.
var NvidiaQuery = []string{
	"--query-gpu=index,name,uuid,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
	"--format=csv,noheader,nounits",
}

// Reading is one GPU at one poll. NaN fields are not reported by the device.
type Reading struct {
	Index, Name, ID, Vendor string
	UtilPercent             float64
	MemUsedBytes            float64
	TempC, PowerW           float64
	// ECC error counts since driver load; NaN when the device or driver does not report them.
	ECCCorrected, ECCUncorrected float64
	// Pod is the Kubernetes pod container the GPU is assigned to (Attribute); Tracked says the
	// kubelet was asked, so a nil Pod means unallocated rather than unknown.
	Pod     *PodGPU
	Tracked bool
}

// NvidiaECCQuery asks nvidia-smi for the ECC counters (a second call: devices without ECC answer
// "[N/A]", and the main query's shape stays fixed).
var NvidiaECCQuery = []string{
	"--query-gpu=index,ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total",
	"--format=csv,noheader,nounits",
}

// ParseNvidiaECC fills the ECC fields of rs (matched by GPU index) from NvidiaECCQuery output.
// XID errors are not in nvidia-smi; they come from the kernel-log tailer (XIDLogPath, see XIDTail).
func ParseNvidiaECC(r io.Reader, rs []Reading) error {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = 3
	rows, err := cr.ReadAll()
	if err != nil {
		return fmt.Errorf("nvidia-smi ecc output: %w", err)
	}
	for _, f := range rows {
		for i := range rs {
			if rs[i].Index == strings.TrimSpace(f[0]) {
				rs[i].ECCCorrected, rs[i].ECCUncorrected = num(f[1]), num(f[2])
			}
		}
	}
	return nil
}

func num(s string) float64 {
	s = strings.TrimSpace(s)
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) {
		return math.NaN() // "[N/A]", "N/A", "[Not Supported]"
	}
	return f
}

// ParseNvidiaCSV parses the output of nvidia-smi with NvidiaQuery. Memory is reported in MiB.
func ParseNvidiaCSV(r io.Reader) ([]Reading, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = 8
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi output: %w", err)
	}
	out := make([]Reading, 0, len(rows))
	for _, f := range rows {
		out = append(out, Reading{
			Index: strings.TrimSpace(f[0]), Name: strings.TrimSpace(f[1]), ID: strings.TrimSpace(f[2]), Vendor: "nvidia",
			UtilPercent: num(f[3]), MemUsedBytes: num(f[4]) * 1024 * 1024, TempC: num(f[6]), PowerW: num(f[7]),
			ECCCorrected: math.NaN(), ECCUncorrected: math.NaN(),
		})
	}
	return out, nil
}

// Emit writes the hw.gpu.* metrics of the readings the discovery rules allow (matched against
// the GPU index).
func Emit(out sink.Sink, d host.Discovery, rs []Reading, at time.Time) {
	for _, r := range rs {
		if !d.Allow(host.KindGPU, r.Index) {
			continue
		}
		id := r.ID
		if id == "" {
			id = r.Vendor + "-" + r.Index
		}
		a := map[string]string{"hw.id": id, "hw.name": r.Name, "hw.vendor": r.Vendor, "gpu.index": r.Index}
		if p := r.Pod; p != nil {
			a["k8s.pod.name"], a["k8s.namespace.name"], a["k8s.container.name"] = p.Pod, p.Namespace, p.Container
		}
		put := func(name, unit string, v float64) {
			if !math.IsNaN(v) {
				out.Gauge(name, unit, v, a, at)
			}
		}
		put("hw.gpu.utilization", "1", r.UtilPercent/100)
		put("hw.gpu.memory.usage", "By", r.MemUsedBytes)
		put("hw.gpu.temperature", "Cel", r.TempC)
		put("hw.gpu.power", "W", r.PowerW)
		if r.Tracked {
			alloc := 0.0
			if r.Pod != nil {
				alloc = 1
			}
			put("hw.gpu.allocated", "1", alloc)
		}
		if r.Vendor == "nvidia" {
			for kind, v := range map[string]float64{"corrected": r.ECCCorrected, "uncorrected": r.ECCUncorrected} {
				if !math.IsNaN(v) {
					out.Sum("hw.gpu.ecc.errors", "{error}", v, sink.With(a, "hw.error.type", kind), at)
				}
			}
		}
	}
}

// run executes a vendor tool with a fixed argv, no shell and a minimal environment.
func run(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=" + pathEnv()}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return buf.Bytes(), nil
}

// Nvidia polls nvidia-smi at path.
func Nvidia(ctx context.Context, path string) ([]Reading, error) {
	b, err := run(ctx, path, NvidiaQuery...)
	if err != nil {
		return nil, err
	}
	rs, err := ParseNvidiaCSV(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	// ECC is optional: a failure here leaves the counters missing, not the poll failed.
	if eb, err := run(ctx, path, NvidiaECCQuery...); err == nil {
		_ = ParseNvidiaECC(bytes.NewReader(eb), rs)
	}
	return rs, nil
}

// Config is the gpu module's config. Only Enabled and Interval can be set remotely; the tool
// paths are local-file only.
type Config struct {
	Enabled       *bool          `json:"enabled"`
	Interval      string         `json:"interval"`        // default 15s, at least 5s
	NvidiaSMIPath string         `json:"nvidia_smi_path"` // empty: nvidia-smi is not run
	RocmSMIPath   string         `json:"rocm_smi_path"`   // empty: rocm-smi is not run
	Discovery     host.Discovery `json:"discovery"`
	// Extended adds per-process memory, MIG slices and NVLink (default true; three more nvidia-smi calls).
	Extended *bool `json:"extended"`
	// XIDLogPath is a kernel log file to tail for NVIDIA Xid events; empty: not read.
	XIDLogPath string `json:"xid_log_path"`
	// PodResourcesSocket is the kubelet pod-resources socket (Kubernetes nodes, e.g.
	// /var/lib/kubelet/pod-resources/kubelet.sock); when set, hw.gpu.* carry the pod that holds
	// each GPU and hw.gpu.allocated is reported. Empty: not asked.
	PodResourcesSocket string `json:"pod_resources_socket"`
}

// Run polls until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out sink.Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if err := c.Discovery.Validate(); err != nil {
		return err
	}
	if c.Enabled != nil && !*c.Enabled || c.NvidiaSMIPath == "" && c.RocmSMIPath == "" && c.XIDLogPath == "" {
		<-ctx.Done()
		return nil
	}
	var xid *XIDTail
	if c.XIDLogPath != "" {
		xid = &XIDTail{Path: c.XIDLogPath}
	}
	t := time.NewTicker(host.Duration(c.Interval, 15*time.Second, 5*time.Second))
	defer t.Stop()
	for {
		now := time.Now()
		pods := c.pods(ctx)
		if c.NvidiaSMIPath != "" {
			if rs, err := Nvidia(ctx, c.NvidiaSMIPath); err == nil {
				if pods != nil {
					Attribute(rs, pods)
				}
				Emit(out, c.Discovery, rs, now)
				if c.Extended == nil || *c.Extended {
					EmitExtras(out, c.Discovery, rs, NvidiaExtras(ctx, c.NvidiaSMIPath), now)
				}
			}
		}
		if xid != nil {
			if xs, err := xid.Poll(); err == nil {
				EmitXID(out, xs, now)
			}
		}
		if c.RocmSMIPath != "" {
			if rs, err := Rocm(ctx, c.RocmSMIPath); err == nil {
				if pods != nil {
					Attribute(rs, pods)
				}
				Emit(out, c.Discovery, rs, now)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// pods is the GPU assignment from the kubelet, or nil when not configured or unavailable (the
// GPUs are then reported without allocation, not as unallocated).
func (c *Config) pods(ctx context.Context) map[string]PodGPU {
	if c.PodResourcesSocket == "" {
		return nil
	}
	m, err := ListPodResources(ctx, c.PodResourcesSocket)
	if err != nil {
		slog.Warn("gpu: kubelet pod-resources unavailable", "error", err)
		return nil
	}
	return m
}
