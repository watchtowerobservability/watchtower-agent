# Changelog

## 0.1.7

- Fix: Docker container logs now carry the container's service identity (`dockerAttrs` and `ResolveIdentity`).
- Fix: eBPF HTTP/2 capture no longer stops decoding a connection direction after a header block cut at the
  512 B capture limit; later requests keep their method and path. Fields only reachable through a lost
  HPACK table entry are left out instead of mis-named.

## 0.1.0

- First public release: `wt-agent` (host, container, Kubernetes, network, logs and custom-check collection
  over OTLP), the Kubernetes operator (`operator/`), the `watchtower-agent` Helm chart, deb/rpm packages and
  a multi-arch container image. Releases carry build provenance attestations.
