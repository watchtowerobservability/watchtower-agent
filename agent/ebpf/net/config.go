package net

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Config is the module's own JSON config. The module is off unless Enabled is set.
type Config struct {
	Enabled         bool   `json:"enabled"`
	Interval        string `json:"interval"`           // aggregation window, default 10s
	MaxEventsPerSec int    `json:"max_events_per_sec"` // default 20000
	RingBufferKB    int    `json:"ring_buffer_kb"`     // default 1024, a power of two
	DNS             *bool  `json:"dns"`                // DNS query telemetry, default true
	ObjectDir       string `json:"object_dir"`         // holds tcp_bpfel.o
	// Zone is this node's zone; ZonePrefixes map peers to zones; ZonesFromK8s also reads node
	// podCIDRs and internal IPs with their topology.kubernetes.io/zone (needs get/list on nodes).
	Zone         string       `json:"zone"`
	ZonePrefixes []ZonePrefix `json:"zone_prefixes"`
	ZonesFromK8s bool         `json:"zones_from_k8s"`
}

// ParseConfig decodes raw (empty means defaults, disabled) and applies defaults.
func ParseConfig(raw json.RawMessage) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("ebpf_net config: %w", err)
		}
	}
	if c.MaxEventsPerSec <= 0 {
		c.MaxEventsPerSec = 20_000
	}
	if c.RingBufferKB <= 0 {
		c.RingBufferKB = 1024
	}
	if c.RingBufferKB&(c.RingBufferKB-1) != 0 || c.RingBufferKB < 64 {
		return c, fmt.Errorf("ring_buffer_kb %d must be a power of two >= 64", c.RingBufferKB)
	}
	if c.ObjectDir == "" {
		c.ObjectDir = "/usr/lib/wt-agent/ebpf"
	}
	if _, err := c.Window(); err != nil {
		return c, err
	}
	return c, nil
}

// Window is the aggregation interval.
func (c Config) Window() (time.Duration, error) {
	if c.Interval == "" {
		return 10 * time.Second, nil
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("interval %q must be a duration of at least 1s", c.Interval)
	}
	return d, nil
}

// WantDNS reports whether DNS telemetry is on.
func (c Config) WantDNS() bool { return c.DNS == nil || *c.DNS }
