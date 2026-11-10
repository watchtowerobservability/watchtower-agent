# Embedded runtime_security eBPF object

`make ebpf-gen` compiles `../bpf/runtimesec.bpf.c` to `runtimesec_bpfel.o` in this directory, where
`loader_linux.go` embeds it with `//go:embed objects`. The `.o` is a `.gitignore`d build artifact,
not checked in. A build that ran `make ebpf-gen` first carries the object and the module turns on
config-only; a build without it embeds nothing and the loader falls back to `object_dir` on disk
(default `/usr/lib/wt-agent/ebpf`), failing preflight with a message that says to run ebpf-gen. This
README is the placeholder that keeps `//go:embed objects` compiling when no object is present.

## How it is built

`scripts/ebpf-gen.sh` already compiles `../bpf/runtimesec.bpf.c` (after the `ebpf` package objects, same
toolchain and `-D__TARGET_ARCH_*`) into `runtimesec_bpfel.o` here. Run it on a Linux host before the agent
release `go build` so the object embeds.

### Object layout the loader expects

- One `BPF_MAP_TYPE_RINGBUF` map named `events` (resized from `ring_buffer_kb`).
- Three programs, attached as `syscalls` tracepoints:
  `enter_execve` -> `sys_enter_execve`, `enter_openat` -> `sys_enter_openat`,
  `enter_connect` -> `sys_enter_connect`.
- Each ring-buffer record is `struct rt_event` (312 bytes, little-endian), mirrored by
  `DecodeEvent` / `EventSize` in `event.go`. Change one, change both.

## Enforcement object

`runtimesec_lsm_bpfel.o` (from `../bpf/runtimesec_lsm.bpf.c`, built by the same `ebpf-gen` step) carries the
BPF LSM programs `wt_bprm_check` (`lsm/bprm_check_security`) and `wt_file_open` (`lsm/file_open`), the hash
maps `deny_exec` and `deny_file` (key: inode + kernel dev, 16 bytes) and the `denied` ring buffer (48-byte
records). It is loaded only when the policy has `block` rules, and only on a kernel whose
`/sys/kernel/security/lsm` lists `bpf`; otherwise the module refuses to start, logs
`runtime_security.block=unavailable` and returns the error to the agent's module status.
