package ebpf

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Config is the module's own JSON config. The module is off unless Enabled is set.
type Config struct {
	Enabled         bool `json:"enabled"`
	SampleHz        int  `json:"sample_hz"`         // per CPU, default 19
	UploadIntervalS int  `json:"upload_interval_s"` // default 60
	OffCPU          bool `json:"offcpu"`            // default true
	OffCPUMinMs     int  `json:"offcpu_min_ms"`     // default 1 (floor)
	// StripProcessArgs drops the command line and keeps only the executable base name.
	// Default true.
	StripProcessArgs *bool `json:"strip_process_args"`
	// PlainPID sends the numeric pid instead of a hash of it. Default false.
	PlainPID bool `json:"plain_pid"`
	// ObjectDir holds cpu_bpfel.o and offcpu_bpfel.o (built by `make ebpf-gen`).
	ObjectDir string `json:"object_dir"`
	// CPUBudget is the self-CPU fraction above which the sample rate is halved. Default 0.01.
	CPUBudget float64 `json:"cpu_budget"`

	// Endpoint and Token are filled in by the agent from its local config, never from JSON.
	Endpoint string `json:"-"`
	Token    string `json:"-"`
}

// ParseConfig decodes raw (empty means defaults, disabled) and applies defaults.
func ParseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("ebpf_profiler config: %w", err)
		}
	}
	c.OffCPU = c.OffCPU || !hasKey(raw, "offcpu")
	if c.SampleHz <= 0 {
		c.SampleHz = 19
	}
	if c.UploadIntervalS <= 0 {
		c.UploadIntervalS = 60
	}
	if c.OffCPUMinMs <= 0 {
		c.OffCPUMinMs = 1
	}
	if c.CPUBudget <= 0 {
		c.CPUBudget = 0.01
	}
	if c.ObjectDir == "" {
		c.ObjectDir = "/usr/lib/wt-agent/ebpf"
	}
	if c.SampleHz > 999 {
		return c, fmt.Errorf("sample_hz %d too high (max 999)", c.SampleHz)
	}
	return c, nil
}

// Strip reports whether process arguments must be removed.
func (c Config) Strip() bool { return c.StripProcessArgs == nil || *c.StripProcessArgs }

func hasKey(raw json.RawMessage, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
