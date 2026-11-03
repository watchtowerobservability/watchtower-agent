// Package runtime is the agent module `runtime_metrics` (CFT-E10): language runtime metrics of
// processes that run no SDK. JVMs publish their counters in the hsperfdata memory-mapped file
// (/tmp/hsperfdata_<user>/<pid>, on by default since JDK 6); the agent reads it like jstat does,
// with no attach, no agent jar and no BPF. Other runtimes (Go, .NET, Node.js, CPython) need
// in-process hooks and are not covered here.
package runtime

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Sink is the metric output (the agent's exporter).
type Sink interface {
	Gauge(name, unit string, value float64, attrs map[string]string, at time.Time)
	Sum(name, unit string, value float64, attrs map[string]string, at time.Time)
}

const perfMagic = 0xcafec0c0

// PerfData holds the long counters and string values of one hsperfdata file.
type PerfData struct {
	Longs   map[string]int64
	Strings map[string]string
}

// ParsePerfData decodes the hsperfdata v2 layout (prologue, then entries).
func ParsePerfData(b []byte) (*PerfData, error) {
	if len(b) < 32 || binary.BigEndian.Uint32(b) != perfMagic {
		return nil, errors.New("not an hsperfdata file")
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if b[4] == 0 {
		bo = binary.BigEndian
	}
	if b[5] != 2 {
		return nil, errors.New("unsupported hsperfdata version")
	}
	off, n := int(bo.Uint32(b[24:])), int(bo.Uint32(b[28:]))
	pd := &PerfData{Longs: map[string]int64{}, Strings: map[string]string{}}
	for i := 0; i < n && off+20 <= len(b); i++ {
		e := b[off:]
		elen, nameOff, vlen, typ, doff := int(bo.Uint32(e)), int(bo.Uint32(e[4:])), int(bo.Uint32(e[8:])), e[12], int(bo.Uint32(e[16:]))
		if elen <= 0 || off+elen > len(b) || nameOff >= elen || doff > elen {
			break
		}
		name, _, _ := bytes.Cut(e[nameOff:elen], []byte{0})
		switch {
		case typ == 'J' && vlen == 0 && doff+8 <= elen:
			pd.Longs[string(name)] = int64(bo.Uint64(e[doff:])) //nolint:gosec // a counter
		case typ == 'B' && vlen > 0 && doff+vlen <= elen:
			s, _, _ := bytes.Cut(e[doff:doff+vlen], []byte{0})
			pd.Strings[string(name)] = string(s)
		}
		off += elen
	}
	return pd, nil
}

// Emit turns the counters into OTel JVM semconv metrics.
func Emit(out Sink, pd *PerfData, attrs map[string]string, at time.Time) {
	freq := float64(pd.Longs["sun.os.hrt.frequency"])
	if freq <= 0 {
		freq = 1e9
	}
	for g := 0; g < 4; g++ {
		for sp := 0; sp < 4; sp++ {
			pre := "sun.gc.generation." + strconv.Itoa(g) + ".space." + strconv.Itoa(sp) + "."
			used, ok := pd.Longs[pre+"used"]
			if !ok {
				continue
			}
			a := with(attrs, "jvm.memory.pool.name", pd.Strings[pre+"name"], "jvm.memory.type", "heap")
			out.Gauge("jvm.memory.used", "By", float64(used), a, at)
			out.Gauge("jvm.memory.committed", "By", float64(pd.Longs[pre+"capacity"]), a, at)
			out.Gauge("jvm.memory.limit", "By", float64(pd.Longs[pre+"maxCapacity"]), a, at)
		}
	}
	if used, ok := pd.Longs["sun.gc.metaspace.used"]; ok {
		out.Gauge("jvm.memory.used", "By", float64(used), with(attrs, "jvm.memory.pool.name", "Metaspace", "jvm.memory.type", "non_heap"), at)
	}
	for c := 0; c < 4; c++ {
		pre := "sun.gc.collector." + strconv.Itoa(c) + "."
		inv, ok := pd.Longs[pre+"invocations"]
		if !ok {
			continue
		}
		a := with(attrs, "jvm.gc.name", pd.Strings[pre+"name"])
		out.Sum("jvm.gc.collections", "{collection}", float64(inv), a, at)
		out.Sum("jvm.gc.duration.total", "s", float64(pd.Longs[pre+"time"])/freq, a, at)
	}
	if v, ok := pd.Longs["java.threads.live"]; ok {
		out.Gauge("jvm.thread.count", "{thread}", float64(v), attrs, at)
	}
	if v, ok := pd.Longs["java.cls.loadedClasses"]; ok {
		out.Gauge("jvm.class.count", "{class}", float64(v-pd.Longs["java.cls.unloadedClasses"]), attrs, at)
	}
	if v, ok := pd.Longs["sun.rt.safepoints"]; ok {
		out.Sum("jvm.safepoints", "{safepoint}", float64(v), attrs, at)
	}
}

func with(base map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(base)+len(kv)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

// Config is the module config: off unless Enabled; Interval default 30s.
type Config struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"`
}

// perfFiles finds hsperfdata files: the agent's own temp dir and, on Linux, each process's
// /tmp through /proc/<pid>/root (JVMs in containers). The key is the host pid when known.
func perfFiles() map[string]string {
	out := map[string]string{}
	local, _ := filepath.Glob(filepath.Join(os.TempDir(), "hsperfdata_*", "*"))
	for _, f := range local {
		out[filepath.Base(f)] = f
	}
	procs, _ := filepath.Glob("/proc/[0-9]*/root/tmp/hsperfdata_*/*")
	for _, f := range procs {
		parts := strings.Split(f, "/")
		if len(parts) > 2 {
			out[parts[2]] = f // a JVM seen through several pids of one container shows once per pid
		}
	}
	return out
}

// Run polls the JVMs every interval until ctx ends.
func Run(ctx context.Context, raw json.RawMessage, out Sink) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	if !c.Enabled {
		<-ctx.Done()
		return nil
	}
	every, err := time.ParseDuration(c.Interval)
	if err != nil || every < 5*time.Second {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		now := time.Now()
		seen := map[string]bool{}
		for pid, f := range perfFiles() {
			b, err := os.ReadFile(f) //nolint:gosec // a path found under hsperfdata_* only
			if err != nil {
				continue
			}
			pd, err := ParsePerfData(b)
			if err != nil {
				continue
			}
			vmid := pd.Strings["sun.rt.javaCommand"] + "|" + strconv.FormatInt(pd.Longs["sun.rt.createVmBeginTime"], 10)
			if seen[vmid] {
				continue
			}
			seen[vmid] = true
			cmd, _, _ := strings.Cut(pd.Strings["sun.rt.javaCommand"], " ")
			Emit(out, pd, map[string]string{"process.pid": pid, "process.runtime.name": "jvm",
				"process.runtime.version": pd.Strings["java.property.java.vm.version"], "process.command": cmd}, now)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
