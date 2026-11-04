package container

import "testing"

func TestResolveIdentityPrecedence(t *testing.T) {
	env := []string{"OTEL_SERVICE_NAME=from-env", "OTEL_RESOURCE_ATTRIBUTES=service.name=ra,deployment.environment.name=prod, service.version=1.2"}
	lab := map[string]string{"com.docker.compose.service": "api"}
	cm := map[string]ServiceMap{"api": {Service: "mapped", Environment: "stage", Version: "9"}}

	// OTEL_SERVICE_NAME env wins over the watchtower label; env also supplies environment/version.
	got := ResolveIdentity(env, map[string]string{"com.watchtower.service": "lbl", "com.docker.compose.service": "api"}, cm, "cname")
	if got.Service != "from-env" || got.Environment != "prod" || got.Version != "1.2" {
		t.Fatalf("env > label: %+v", got)
	}
	// Resource attrs service.name when OTEL_SERVICE_NAME is absent; map fills the rest.
	if got = ResolveIdentity([]string{"OTEL_RESOURCE_ATTRIBUTES=service.name=ra"}, lab, cm, "cname"); got.Service != "ra" || got.Environment != "stage" || got.Version != "9" {
		t.Fatalf("resource attrs then map: %+v", got)
	}
	// com.watchtower.service label beats the map when there is no env.
	if got = ResolveIdentity(nil, map[string]string{"com.watchtower.service": "lbl", "com.docker.compose.service": "api"}, cm, "cname"); got.Service != "lbl" {
		t.Fatalf("label > map: %+v", got)
	}
	// compose-service map when no env or label.
	if got = ResolveIdentity(nil, lab, cm, "cname"); got.Service != "mapped" {
		t.Fatalf("map: %+v", got)
	}
	// compose service name when no map entry.
	if got = ResolveIdentity(nil, lab, nil, "cname"); got.Service != "api" {
		t.Fatalf("compose service name: %+v", got)
	}
	// nothing resolves: service.name falls back to the container name, never the agent's own.
	if got = ResolveIdentity(nil, nil, cm, "cname"); got.Service != "cname" || got.Resource()["service.name"] != "cname" {
		t.Fatalf("container-name fallback: %+v", got)
	}
}

func TestPromName(t *testing.T) {
	cases := map[string]string{
		"container.cpu.usage":    "container_cpu_usage",
		"container.memory.usage": "container_memory_usage",
		"already_ok":             "already_ok",
		"a.b-c/d":                "a_b_c_d",
		"ns:metric.name":         "ns:metric_name",
	}
	for in, want := range cases {
		if got := PromName(in); got != want {
			t.Fatalf("PromName(%q) = %q, want %q", in, got, want)
		}
	}
}
