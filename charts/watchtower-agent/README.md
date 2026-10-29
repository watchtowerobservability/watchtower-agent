# watchtower-agent chart

DaemonSet running `wt-agent` on every node, with an OpenShift SCC and an opt-in injection webhook.

    helm install wta ./watchtower-agent --set endpoint=https://ingest.example.com:4318 --set tokenSecret=wt-agent-token

The token is a `wti_` credential with scope `agent:fleet`, kept in the Secret named by `tokenSecret`.
Registration is subject to the org's `monitored_hosts` and `fleet_agents` limits (HTTP 422 when exceeded).
The `WatchtowerAgent` CRD (`crds/`) is the declarative form of the same values for the operator.
`injection.enabled` needs the operator to serve `/mutate`; with `failurePolicy: Ignore` an outage never blocks pods.
