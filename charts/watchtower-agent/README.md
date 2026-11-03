# watchtower-agent chart

DaemonSet running `wt-agent` on every node, with an OpenShift SCC and an opt-in injection webhook.

    helm install wta ./watchtower-agent --set endpoint=https://ingest.example.com:4318 --set tokenSecret=wt-agent-token

The token is a `wti_` credential with scope `agent:fleet`, kept in the Secret named by `tokenSecret`.
Registration is subject to the org's `monitored_hosts` and `fleet_agents` limits (HTTP 422 when exceeded).
The `WatchtowerAgent` CRD (`crds/`) is the declarative form of the same values for the operator.
`injection.enabled` needs the operator to serve `/mutate`; with `failurePolicy: Ignore` an outage never blocks pods.
Annotate a pod `watchtower.dev/inject-java|nodejs|python|dotnet|php|ruby|go|httpd|nginx: "true"` (or target namespaces and workloads with the operator's `WT_AUTOINST_TARGETS`) to also add OTel auto-instrumentation (init container + loader env; `go` needs `watchtower.dev/otel-go-target-exe`; `httpd`/`nginx` load the OTel webserver module into a staged copy of the config dir, overridable with `watchtower.dev/otel-webserver-conf-dir`). `httpd`/`nginx` need no shell in the app image: a static helper (`wt-webloader`, from the Watchtower image named by the operator's `WT_WEBLOADER_IMAGE`) does the staging, so distroless images work. PHP and Ruby have no default image: push the ones `.illuminati/autoinst.yml` and `infra/docker/autoinst-*.Dockerfile` build and set them with the chart's `operator.autoinstImages` (the operator's `WT_AUTOINST_IMAGE_<LANG>`, which also overrides any other language). Until an image is configured, a pod that asks for it starts uninstrumented and gets the annotation `watchtower.dev/autoinst-status` (and an admission warning) saying which variable to set. Hosts outside Kubernetes use the agent's `autoinst` module (see `infra/agent/agent.example.yaml`).

## RBAC

The ClusterRole is read-only and covers nodes, pods, namespaces, services, endpoints, ingresses and the Prometheus Operator kinds (for `prometheus_operator` discovery and the `prometheus_rules` module). It grants no secret access. `${k8s:namespace/name#key}` references need a named grant:

    helm upgrade wta ./watchtower-agent --set-json 'rbac.secretRefs=[{"namespace":"monitoring","names":["db-credentials"]}]'

That creates a Role per namespace with `get` on those names only. Without it the reference fails with a forbidden error and the module does not start.
