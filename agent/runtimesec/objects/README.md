# Embedded runtime_security eBPF object

`make ebpf-gen` compiles `../bpf/runtimesec.bpf.c` to `runtimesec_bpfel.o` in this directory, where
`loader_linux.go` embeds it with `//go:embed objects`. The `.o` is a `.gitignore`d build artifact,
not checked in. A build that ran `make ebpf-gen` first carries the object and the module turns on
config-only; a build without it embeds nothing and the loader falls back to `object_dir` on disk
(default `/usr/lib/wt-agent/ebpf`), failing preflight with a message that says to run ebpf-gen. This
README is the placeholder that keeps `//go:embed objects` compiling when no object is present.

## What ebpf-gen must add (cross-cutting, see loader_linux.go)

`scripts/ebpf-gen.sh` compiles the objects for the `ebpf` package from `go/agent/ebpf/bpf/`. It must
also compile this module's source. Add `runtimesec` to its build list, sourced from this package:

    clang -O2 -g -target bpf -D__TARGET_ARCH_$a -I/usr/include/$arch-linux-gnu \
        -c go/agent/runtimesec/bpf/runtimesec.bpf.c -o go/agent/runtimesec/objects/runtimesec_bpfel.o

### Object layout the loader expects

- One `BPF_MAP_TYPE_RINGBUF` map named `events` (resized from `ring_buffer_kb`).
- Three programs, attached as `syscalls` tracepoints:
  `enter_execve` -> `sys_enter_execve`, `enter_openat` -> `sys_enter_openat`,
  `enter_connect` -> `sys_enter_connect`.
- Each ring-buffer record is `struct rt_event` (312 bytes, little-endian), mirrored by
  `DecodeEvent` / `EventSize` in `event.go`. Change one, change both.
