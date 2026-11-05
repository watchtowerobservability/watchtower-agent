# syntax=docker/dockerfile:1.7
# Multi-arch: the build runs on the builder's own arch and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends clang libbpf-dev linux-libc-dev bpftool && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# eBPF probes embed into the linux binary (loaders are //go:build linux). The builder runs on the
# build host's arch (BUILDPLATFORM) and cross-compiles; BPF bytecode is arch-neutral but for the
# PT_REGS macros the __TARGET_ARCH define selects, so compile the objects for the target arch.
# tls, rtregs and the *_dwarf probes include a vmlinux.h dumped from BTF; every object is required.
# shortcut: `docker build` has no /sys/kernel/btf of its own (it is the build host's kernel, and
# absent under some builders/BuildKit sandboxes), so this image build fails there. The shipped
# deb/rpm/tarball artifacts come from release.yml, which dumps the runner's BTF. Upgrade: COPY a
# vendored per-arch vmlinux.h.
RUN a=x86; [ "$TARGETARCH" = arm64 ] && a=arm64; \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > agent/ebpf/bpf/vmlinux.h && \
    test -s agent/ebpf/bpf/vmlinux.h && \
    for d in agent/ebpf agent/runtimesec; do for src in "$d"/bpf/*.bpf.c; do \
      clang -O2 -g -target bpf -D__TARGET_ARCH_$a -I/usr/include/x86_64-linux-gnu -I"$d/bpf" \
        -c "$src" -o "$d/objects/$(basename "${src%.bpf.c}")_bpfel.o" || exit 1; done; done; \
    for o in agent/ebpf/objects/cpu agent/ebpf/objects/cpu_dwarf agent/ebpf/objects/offcpu agent/ebpf/objects/offcpu_dwarf agent/ebpf/objects/lock agent/ebpf/objects/rtregs agent/ebpf/objects/http agent/ebpf/objects/tls agent/ebpf/objects/tcp agent/runtimesec/objects/runtimesec; do \
      test -s "${o}_bpfel.o" || { echo "missing ${o}_bpfel.o" >&2; exit 1; }; done
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o /out/wt-agent ./agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wt-agent /wt-agent
ENTRYPOINT ["/wt-agent"]
