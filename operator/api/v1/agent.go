package v1

import (
	"strconv"
	"strings"
)

// AgentResource and AgentKind identify the WatchtowerAgent custom resource (same group/version).
const (
	AgentResource = "watchtoweragents"
	AgentKind     = "WatchtowerAgent"
)

// InjectAnnotation on a pod (or its namespace label) opts it into endpoint injection; the value
// "false" opts out.
const InjectAnnotation = "watchtower.dev/inject"

// AgentSpec is the desired node agent rollout. The token itself is never in the spec, only the
// name of the Secret that holds it.
type AgentSpec struct {
	Version     string            `json:"version"`
	Endpoint    string            `json:"endpoint"`
	TokenSecret string            `json:"tokenSecret"`
	Labels      map[string]string `json:"labels,omitempty"`
	Injection   bool              `json:"injection,omitempty"`
	Paused      bool              `json:"paused,omitempty"`
}

// AgentStatus is the observed DaemonSet state.
type AgentStatus struct {
	Ready           int    `json:"ready,omitempty"`
	Desired         int    `json:"desired,omitempty"`
	ObservedVersion string `json:"observedVersion,omitempty"`
}

// WatchtowerAgent is the custom resource for the node agent.
type WatchtowerAgent struct {
	Name      string      `json:"name"`
	Namespace string      `json:"namespace"`
	Spec      AgentSpec   `json:"spec"`
	Status    AgentStatus `json:"status"`
}

// PatchOp is one RFC 6902 operation of an admission response.
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// InjectPatch is the admission patch for a pod: it adds OTEL_EXPORTER_OTLP_ENDPOINT to every
// container that does not set it, pointing at the agent on the pod's node (hostIP). Pods that
// opt out, or already set the variable, are left alone (nil patch). existing[i] lists the env
// names of container i.
func InjectPatch(annotations map[string]string, existing [][]string, hostIP string, port int) []PatchOp {
	if strings.EqualFold(annotations[InjectAnnotation], "false") || hostIP == "" {
		return nil
	}
	const name = "OTEL_EXPORTER_OTLP_ENDPOINT"
	value := "http://" + hostIP + ":" + strconv.Itoa(port)
	var ops []PatchOp
	for i, envs := range existing {
		has := false
		for _, e := range envs {
			has = has || e == name
		}
		if has {
			continue
		}
		entry := map[string]string{"name": name, "value": value}
		base := "/spec/containers/" + strconv.Itoa(i) + "/env"
		if len(envs) == 0 {
			ops = append(ops, PatchOp{Op: "add", Path: base, Value: []map[string]string{entry}})
		} else {
			ops = append(ops, PatchOp{Op: "add", Path: base + "/-", Value: entry})
		}
	}
	return ops
}
