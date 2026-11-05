# syntax=docker/dockerfile:1.7
# Multi-arch: the build runs on the builder's own arch and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends clang libbpf-dev linux-libc-dev && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# eBPF probes embed into the linux binary (loaders are //go:build linux). The builder runs on the
# build host's arch (BUILDPLATFORM) and cross-compiles; BPF bytecode is arch-neutral but for the
# PT_REGS macros the __TARGET_ARCH define selects, so compile the objects for the target arch.
# The CO-RE/DWARF probes (tcp, rtregs, *_dwarf) need a BTF vmlinux.h this recipe does not build and
# are skipped (loader falls back); the runtimesec workload-protection object is required.
RUN a=x86; [ "$TARGETARCH" = arm64 ] && a=arm64; \
    for d in agent/ebpf agent/runtimesec; do for src in "$d"/bpf/*.bpf.c; do \
      clang -O2 -g -target bpf -D__TARGET_ARCH_$a -I/usr/include/x86_64-linux-gnu \
        -c "$src" -o "$d/objects/$(basename "${src%.bpf.c}")_bpfel.o" || echo "skip (needs BTF): $src"; done; done; \
    test -f agent/runtimesec/objects/runtimesec_bpfel.o
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o /out/wt-agent ./agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wt-agent /wt-agent
ENTRYPOINT ["/wt-agent"]
