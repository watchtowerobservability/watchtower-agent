# Changelog

## 0.1.10

- Shared hosts, with the Docker socket: `scope: self` (or `WT_AGENT_SCOPE=self`) on `container`, `logs.docker` and `cgroups` limits the agent to its own compose project. It inspects only itself, filters by the project label on the Docker side, re-checks every event, and collects nothing if the project can't be found. With the socket mounted and no scope on a host with several projects, it warns.
- Shared hosts, without the socket: `cgroups.parent` (or `WT_AGENT_CGROUP_PARENT`) selects only containers under a `cgroup_parent` slice, in both the systemd and cgroupfs layouts. `cgroups.include` and `cgroups.exclude` take path globs. The module logs a line when it auto-starts.
- `logs.forward`: a Fluent forward listener for Docker's `fluentd` log driver. Logs, container names and labels (`labels-regex`) arrive without the socket, and the cgroup series pick up the learned names and labels.
- Container lifecycle without the socket: start/die/oom events, `container.restarts` and `container.oom_kills` from the cgroup tree.
- Health probes: a `wt.health` label (`http://:3000/healthz`, `tcp://`, `postgres://`, `redis://`) or a static `health:` list emits `container.health` and `container.health.latency` with `source=probe`.
- `require_labels` label values may be a list (any of). `wt-agent explain` lists the running containers a config selects.
- Kubernetes: the `kubernetes` module with `namespaces`, `exclude_namespaces` and `selector` runs with only a namespaced Role. It reads pod metrics from `metrics.k8s.io`, logs from `pods/log`, and events and pod status per namespace. The Helm chart has `scope: namespace` (a Deployment with a Role per namespace, no ClusterRole, no host mounts).

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
