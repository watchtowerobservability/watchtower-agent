package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Config is the module's own JSON config. The module is off unless Enabled is set.
type Config struct {
	Enabled         bool   `json:"enabled"`
	Interval        string `json:"interval"`           // accepted for the remote toggle overlay, unused
	MaxEventsPerSec int    `json:"max_events_per_sec"` // default 20000
	RingBufferKB    int    `json:"ring_buffer_kb"`     // default 4096, a power of two
	TLS             *bool  `json:"tls"`                // uprobes on SSL_write/SSL_read and Go crypto/tls, default true
	ObjectDir       string `json:"object_dir"`         // holds http_bpfel.o and tls_bpfel.o
}

// ParseConfig decodes raw (empty means defaults, disabled) and applies defaults.
func ParseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("ebpf_trace config: %w", err)
		}
	}
	if c.MaxEventsPerSec <= 0 {
		c.MaxEventsPerSec = 20_000
	}
	if c.RingBufferKB <= 0 {
		c.RingBufferKB = 4096
	}
	if c.RingBufferKB&(c.RingBufferKB-1) != 0 || c.RingBufferKB < 64 {
		return c, fmt.Errorf("ring_buffer_kb %d must be a power of two >= 64", c.RingBufferKB)
	}
	if c.ObjectDir == "" {
		c.ObjectDir = "/usr/lib/wt-agent/ebpf"
	}
	return c, nil
}

// WantTLS reports whether the TLS uprobes are on.
func (c Config) WantTLS() bool { return c.TLS == nil || *c.TLS }
