// Package ebpf is the wt-agent module `ebpf_profiler`: whole-system on-CPU and off-CPU
// profiling (PRF-008, PRF-010) with eBPF. Linux only (kernel >= 5.8 with BTF, root or
// CAP_BPF+CAP_PERFMON); other platforms compile stubs whose Preflight returns ErrUnsupported.
//
// The kernel side counts samples per (pid, user stack id, kernel stack id). Every
// upload_interval_s the module folds those counts into one pprof profile per service and posts
// it to /v1/profiles. User frames leave the host as module + build id + module-relative
// address (the server symbolizes); kernel frames are resolved here from /proc/kallsyms; JIT
// frames come from the runtime's perf map (Python 3.12 -X perf, Ruby --yjit-perf, Node
// --perf-basic-prof, JVM perf-map-agent, .NET DOTNET_PerfMapEnabled=1 or runtime_stacks
// "dotnet"), read inside the process's container under its namespace pid, else from the host
// /tmp/perf-<pid>.map.
//
// User stacks are unwound with DWARF call frame information on x86-64 and arm64 (dwarf_unwind,
// default on): ehframe.go parses each sampled binary's .eh_frame (else .debug_frame) into compact
// rows, unwind_tables.go shares them per build id and ships them to BPF maps with per-process
// mapping lists (at most 1024 processes, 2^19 rows, 2^17 rows a binary, 64 new processes a window),
// and bpf/dwarf.h walks up to 64 frames with them (4 frames per tail call, so each program stays
// small for the verifier), using frame pointers for PCs without a row (JIT code, CFA expressions).
// A process is unwound this way from the window after its first sample. On Linux 5.15+,
// bpf_task_pt_regs also gives user registers for CPU samples taken in the kernel. Off-CPU stacks
// use frame pointers unless offcpu_dwarf is set: walking on every blocking context switch has
// unmeasured overhead, so it is off by default. Everything uses frame pointers when
// cpu_dwarf_bpfel.o is missing.
//
// python_stacks (default on, CPython 3.13+) and runtime_stacks (default none: "python_legacy" for
// CPython 3.11 and 3.12, "ruby", "php", "node", "jvm") read runtime-level stacks from process memory with process_vm_readv at 19 Hz,
// posted as python_wall, ruby_wall, php_wall, node_cpu and jvm_wall. The target is never stopped or
// written to. Layouts come from the runtime itself where it publishes them (CPython 3.13+, V8,
// HotSpot) and from per-version tables otherwise (CPython 3.11-3.12, Ruby, PHP). Each attach runs
// a self-check, and a refusal is logged with its reason. All readers share read caps
// that the CPU guard halves when the agent is over budget.
//
// lock_contention (default off) counts the nanoseconds threads wait in pthread_mutex_lock and the
// pthread rwlock calls (bpf/lock.bpf.c: uprobe + uretprobe on the host libc, or the files in
// lock_libs), waits under lock_min_us dropped in the kernel, posted as lock_contention by caller
// stack. lock_futex adds untimed futex waits and PI lock syscalls outside those calls.
package ebpf

import "errors"

// ErrUnsupported is returned by Preflight on platforms without eBPF support.
var ErrUnsupported = errors.New("ebpf profiler: unsupported on this platform (Linux only)")
