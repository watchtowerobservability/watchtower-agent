# syntax=docker/dockerfile:1.7
# Multi-arch: the build runs on the builder's own arch and cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o /out/wt-agent ./agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wt-agent /wt-agent
ENTRYPOINT ["/wt-agent"]
