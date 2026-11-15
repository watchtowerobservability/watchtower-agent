# Changelog

## 0.1.9

- Fix: with `read_only: true`, `cap_drop: [ALL]` and no mounts the agent no longer loops on `register failed ... read-only file system`. The state dir falls back to `$XDG_STATE_HOME/wt-agent`, then `$TMPDIR` or `/tmp/wt-agent` (one warning names the choice); failing to persist the agent id is a warning, not a registration error.
- `cgroups` module: container metrics from `/sys/fs/cgroup` start by themselves when there is no Docker socket.
- `wt-agent health` exits non-zero until registered and exporting; the image HEALTHCHECK uses it.
- Stable identity: the host key is the hashed machine id (`/etc/machine-id`, `/host/etc/machine-id`), else a persisted id, else a hostname hash; the server upserts on it, so retries and restarts reuse one agent row.
- Startup logs which containers matched the label filter; `WT_AGENT_DOCKER_PROJECT=<project>` is shorthand for `com.docker.compose.project=<project>`.
- `wt-agent postgres bootstrap --dsn <dsn> [--print]` runs (or prints) the least-privilege `wt_monitor` role SQL (`pg_monitor` + `CONNECT`).

## 0.1.8

- Fix: modules set to `enabled: false` are no longer listed as active in the startup log.
- Unknown keys in the agent config are reported as a warning at startup (the agent still starts).

## 0.1.7

- Fix: Docker container logs now carry the container's service identity (`dockerAttrs` and `ResolveIdentity`).
- Fix: eBPF HTTP/2 capture no longer stops decoding a connection direction after a header block cut at the
  512 B capture limit; later requests keep their method and path. Fields only reachable through a lost
  HPACK table entry are left out instead of mis-named.

## 0.1.0

- First public release: `wt-agent` (host, container, Kubernetes, network, logs and custom-check collection
  over OTLP), the Kubernetes operator (`operator/`), the `watchtower-agent` Helm chart, deb/rpm packages and
  a multi-arch container image. Releases carry build provenance attestations.
