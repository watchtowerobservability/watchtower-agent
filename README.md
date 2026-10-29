# watchtower-agent

[![CI](https://github.com/watchtowerobservability/watchtower-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-agent/actions/workflows/ci.yml)

The Watchtower host agent (`wt-agent`) and the Kubernetes operator. The agent collects host, container,
Kubernetes, network, log and custom-check telemetry and ships it to the hosted Watchtower over OTLP with
your ingest key. This repository is a snapshot mirror of the Watchtower monorepo; open issues here.

## Install

| Method | How |
| --- | --- |
| Binary | Download `wt-agent-<os>-<arch>` (tar.gz, zip on Windows) from [Releases](https://github.com/watchtowerobservability/watchtower-agent/releases), check it against `SHA256SUMS`, put it on `PATH`. Linux, macOS, Windows; amd64 and arm64. |
| Script (Linux, macOS) | Download `infra/agent/install.sh` and read it, then `sudo sh install.sh --base-url https://github.com/watchtowerobservability/watchtower-agent/releases/download/v0.1.0 --sha256 <tarball sha256>`. It verifies the checksum before unpacking and never pipes into a shell. |
| deb / rpm | `wt-agent_<version>_<arch>.deb` / `.rpm` from Releases (systemd unit, `wt-agent` user, config in `/etc/wt-agent/agent.yaml`). |
| Docker | `docker run ghcr.io/watchtowerobservability/agent:0.1.0` (distroless, multi-arch). |
| Helm | `helm install wta oci://ghcr.io/watchtowerobservability/charts/watchtower-agent --version 0.1.0 --set endpoint=https://ingest.example.com:4318 --set tokenSecret=wt-agent-token --set image.repository=ghcr.io/watchtowerobservability/agent` |
| Fleet | Run with `fleetMode: opamp` to be managed through the OpAMP fleet API (remote config, rollouts, named commands). |

## Quick start

```sh
export WT_INGEST_KEY=wti_...                  # agent:fleet scoped key, from your Watchtower project
export WT_OTLP_ENDPOINT=https://ingest.example.com:4318
wt-agent --version
wt-agent                                       # config: infra/agent/agent.example.yaml
```

The key is sent as `Authorization: Bearer <key>` and never logged.

## Kubernetes operator

`operator/` reconciles the `WatchtowerAgent` custom resource (CRD in `charts/watchtower-agent/crds`) into the
DaemonSet and serves the opt-in pod-injection webhook. The Helm chart in `charts/watchtower-agent` is the
supported way to run both.

## Configuration

| Variable | Meaning | Default |
| --- | --- | --- |
| `WT_INGEST_KEY` | Secret key (never printed) | none |
| `WT_OTLP_ENDPOINT` | OTLP/HTTP base URL | `http://localhost:4318` |
| `WT_SERVICE`, `WT_ENVIRONMENT`, `WT_RELEASE` | Resource attributes | unset |

Full agent options: `infra/agent/agent.example.yaml`.

## Verify a download

```sh
gh attestation verify <file> --repo watchtowerobservability/watchtower-agent
```

For the image: `gh attestation verify oci://ghcr.io/watchtowerobservability/agent:0.1.0 --repo watchtowerobservability/watchtower-agent`.

## License

Apache-2.0, see `LICENSE`.
