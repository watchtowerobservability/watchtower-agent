// Package v1 holds the WatchtowerCluster.watchtower.dev/v1alpha1 types. They are plain structs
// converted to and from unstructured objects, so the operator needs no generated clients.
package v1

// Group, Version, Resource and Kind identify the custom resource.
const (
	Group    = "watchtower.dev"
	Version  = "v1alpha1"
	Resource = "watchtowerclusters"
	Kind     = "WatchtowerCluster"
)

// Phase is the coarse lifecycle state in Status.Phase.
type Phase string

// The phases of a WatchtowerCluster.
const (
	PhasePending    Phase = "Pending"
	PhaseMigrating  Phase = "Migrating"
	PhaseRollingOut Phase = "RollingOut"
	PhaseReady      Phase = "Ready"
	PhaseDegraded   Phase = "Degraded"
)

// WorkerScaling bounds the lag-driven worker replica count.
type WorkerScaling struct {
	Min           int   `json:"min"`
	Max           int   `json:"max"`
	LagPerReplica int64 `json:"lagPerReplica"`
}

// Spec is the desired state. Replicas maps a service (the Deployment's component label) to a
// replica count; services absent from it keep the Deployment's current count.
type Spec struct {
	Version       string         `json:"version"`
	Replicas      map[string]int `json:"replicas,omitempty"`
	WorkerScaling *WorkerScaling `json:"workerScaling,omitempty"`
	Maintenance   bool           `json:"maintenance,omitempty"`
	Paused        bool           `json:"paused,omitempty"`
}

// Condition is one observed fact, in the usual Kubernetes shape.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}

// Status is the observed state.
type Status struct {
	Phase           Phase          `json:"phase,omitempty"`
	ObservedVersion string         `json:"observedVersion,omitempty"`
	Conditions      []Condition    `json:"conditions,omitempty"`
	Services        map[string]int `json:"services,omitempty"` // ReadyReplicas per service
}

// WatchtowerCluster is the custom resource; its name equals the Helm release name.
type WatchtowerCluster struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Spec      Spec   `json:"spec"`
	Status    Status `json:"status"`
}
