package ebpf

import (
	"bytes"
	"encoding/json"
	"errors"
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
	// ObjectDir holds cpu_bpfel.o, cpu_dwarf_bpfel.o, offcpu_bpfel.o and friends (built by `make ebpf-gen`).
	ObjectDir string `json:"object_dir"`
	// CPUBudget is the self-CPU fraction above which the sample rate is halved. Default 0.01.
	CPUBudget float64 `json:"cpu_budget"`
	// DwarfUnwind walks user stacks with the binaries' .eh_frame / .debug_frame (x86-64), so
	// code built without frame pointers gets whole stacks. Default true; falls back to frame
	// pointers when cpu_dwarf_bpfel.o is missing or does not load.
	DwarfUnwind bool `json:"dwarf_unwind"`
	// OffCPUDwarf also walks off-CPU stacks with those tables, on every blocking context switch
	// of a process with a table. Its overhead on a busy host is unmeasured, so the default is
	// false: off-CPU stacks use frame pointers. Needs dwarf_unwind and Linux 5.15+.
	OffCPUDwarf bool `json:"offcpu_dwarf"`
	// PythonStacks reads Python-level stacks of CPython 3.13+ processes from their memory
	// (process_vm_readv: root or CAP_SYS_PTRACE). Default true.
	PythonStacks bool `json:"python_stacks"`
	// RuntimeStacks names more runtimes to read the same way: "ruby", "php", "node", "jvm", and
	// "python_legacy" for CPython 3.11 and 3.12 (needs python_stacks). "dotnet" instead asks each
	// .NET 8+ process, once, through its diagnostics socket to write a perf map for its JIT frames.
	// Default none: their overhead is unmeasured and they have not run on Linux.
	RuntimeStacks []string `json:"runtime_stacks"`
	// LockContention counts the time threads wait in pthread_mutex_lock and the pthread rwlock
	// calls (uprobes on libc), posted as lock_contention. Default false: a uprobe costs about a
	// microsecond on every lock call, contended or not.
	LockContention bool `json:"lock_contention"`
	// LockMinUs drops waits shorter than this many microseconds. Default 10.
	LockMinUs int `json:"lock_min_us"`
	// LockLibs are the libraries to hook (default: the host's libc and libpthread). A container
	// with its own libc is hooked by naming its file, e.g. /proc/<pid>/root/lib/libc.so.6.
	LockLibs []string `json:"lock_libs"`
	// LockFutex also counts untimed futex waits and PI lock syscalls made outside those calls
	// (static binaries, other runtimes). Condition waits without a timeout count too.
	LockFutex bool `json:"lock_futex"`

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
	c.DwarfUnwind = c.DwarfUnwind || !hasKey(raw, "dwarf_unwind")
	c.PythonStacks = c.PythonStacks || !hasKey(raw, "python_stacks")
	if c.SampleHz <= 0 {
		c.SampleHz = 19
	}
	if c.UploadIntervalS <= 0 {
		c.UploadIntervalS = 60
	}
	if c.OffCPUMinMs <= 0 {
		c.OffCPUMinMs = 1
	}
	if c.LockMinUs <= 0 {
		c.LockMinUs = 10
	}
	if (len(c.LockLibs) > 0 || c.LockFutex) && !c.LockContention {
		return c, errors.New("lock_libs and lock_futex need lock_contention")
	}
	if c.CPUBudget <= 0 {
		c.CPUBudget = 0.01
	}
	if c.ObjectDir == "" {
		c.ObjectDir = "/usr/lib/wt-agent/ebpf"
	}
	for _, r := range c.RuntimeStacks {
		if r != "ruby" && r != "php" && r != "node" && r != "jvm" && r != "python_legacy" && r != "dotnet" {
			return c, fmt.Errorf("runtime_stacks: unknown runtime %q (ruby, php, node, jvm, python_legacy, dotnet)", r)
		}
		if r == "python_legacy" && !c.PythonStacks {
			return c, errors.New("runtime_stacks: python_legacy needs python_stacks")
		}
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

// defaultLockLibs are where distributions keep libc and libpthread (glibc before 2.34 has the
// lock calls in libpthread) and musl's libc.
var defaultLockLibs = []string{
	"/lib/x86_64-linux-gnu/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6", "/lib64/libc.so.6",
	"/usr/lib64/libc.so.6", "/lib/x86_64-linux-gnu/libpthread.so.0",
	"/lib/aarch64-linux-gnu/libpthread.so.0", "/lib64/libpthread.so.0",
	"/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1",
}

// LockLibraries is lock_libs, or the default paths that resolve (by resolve, which follows
// symlinks), each real file once so a /lib64 -> /usr/lib64 link is not hooked twice.
func (c Config) LockLibraries(resolve func(string) (string, error)) []string {
	if len(c.LockLibs) > 0 {
		return c.LockLibs
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range defaultLockLibs {
		file, err := resolve(p)
		if err != nil || seen[file] {
			continue
		}
		seen[file] = true
		out = append(out, p)
	}
	return out
}
