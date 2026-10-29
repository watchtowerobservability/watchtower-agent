// Package ebpf is the wt-agent module `ebpf_profiler`: whole-system on-CPU and off-CPU
// profiling (PRF-008, PRF-010) with eBPF. Linux only (kernel >= 5.8 with BTF, root or
// CAP_BPF+CAP_PERFMON); other platforms compile stubs whose Preflight returns ErrUnsupported.
//
// The kernel side counts samples per (pid, user stack id, kernel stack id). Every
// upload_interval_s the module folds those counts into one pprof profile per service and posts
// it to /v1/profiles. User frames leave the host as module + build id + module-relative
// address (the server symbolizes); kernel frames are resolved here from /proc/kallsyms; JIT
// frames come from /tmp/perf-<pid>.map when the runtime writes one.
package ebpf

import "errors"

// ErrUnsupported is returned by Preflight on platforms without eBPF support.
var ErrUnsupported = errors.New("ebpf profiler: unsupported on this platform (Linux only)")
