# Embedded eBPF objects

`make ebpf-gen` (scripts/ebpf-gen.sh, Linux + clang) writes the compiled CO-RE objects
(`{cpu,cpu_dwarf,offcpu,offcpu_dwarf,lock,rtregs,http,tls,tcp}_bpfel.o`) into this directory. They
are `.gitignore`d build artifacts, not checked in. `objects_linux.go` embeds whatever `*.o` sit
here at `go build` time, so a release image that ran `make ebpf-gen` first carries the objects and
every eBPF module (profiler, `ebpf_trace`, `ebpf_net`) turns on config-only. A build without that
step embeds nothing and the agent falls back to `object_dir` on disk (default
`/usr/lib/wt-agent/ebpf`). This placeholder keeps the `//go:embed objects` directive compiling when
no object is present.
