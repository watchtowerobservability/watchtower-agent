package container

import "strings"

// ServiceMap names the service a compose service stands for (agent.yaml, modules.container.services).
type ServiceMap struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
}

// Identity is the application a container runs, as the product shows it.
type Identity struct{ Service, Environment, Version string }

func (i Identity) empty() bool { return i.Service == "" }

// Resource returns the OTLP resource attributes (unprefixed) for the identity; nil when unknown.
// wt.internal=false overrides the agent's own marker (the agent resource carries wt.internal=true).
func (i Identity) Resource() map[string]string {
	if i.empty() {
		return nil
	}
	r := map[string]string{"service.name": i.Service, "wt.internal": "false"}
	if i.Environment != "" {
		r["deployment.environment.name"] = i.Environment
	}
	if i.Version != "" {
		r["service.version"] = i.Version
	}
	return r
}

// ResolveIdentity picks service.name, per W62, from the first non-empty of: the container's
// OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES service.name env, a com.watchtower.service label,
// the agent.yaml compose-service map, the compose service name, then the container name. The
// environment and version resolve likewise (env, label, map). name is the last-resort service so
// a scraped container never inherits the agent's own service.name (wt-agent); pass "" for none.
func ResolveIdentity(env []string, labels map[string]string, byCompose map[string]ServiceMap, name string) Identity {
	ev := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			ev[k] = v
		}
	}
	ra := map[string]string{}
	for _, kv := range strings.Split(ev["OTEL_RESOURCE_ATTRIBUTES"], ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			ra[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	compose := labels["com.docker.compose.service"]
	m := byCompose[compose]
	first := func(vs ...string) string {
		for _, v := range vs {
			if v != "" {
				return v
			}
		}
		return ""
	}
	return Identity{
		Service: first(ev["OTEL_SERVICE_NAME"], ra["service.name"], labels["com.watchtower.service"], m.Service, compose, name),
		Environment: first(ra["deployment.environment.name"], ra["deployment.environment"],
			labels["com.watchtower.environment"], m.Environment),
		Version: first(ra["service.version"], labels["com.watchtower.version"], m.Version),
	}
}
