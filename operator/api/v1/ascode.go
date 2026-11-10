package v1

// The as-code custom resources: the CR spec is exactly the `spec` of the same-named wtctl
// manifest kind (Monitor, Slo, Dashboard), so a manifest pasted into a CR needs no translation.
const (
	MonitorKind   = "WatchtowerMonitor"
	SLOKind       = "WatchtowerSLO"
	DashboardKind = "WatchtowerDashboard"
)

// AsCodeKind describes one as-code custom resource.
type AsCodeKind struct {
	Kind     string // CR kind
	Resource string // CR plural
	AsCode   string // internal/ascode kind
}

// AsCodeKinds are the CRs the as-code reconciler watches.
var AsCodeKinds = []AsCodeKind{
	{MonitorKind, "watchtowermonitors", "Monitor"},
	{SLOKind, "watchtowerslos", "Slo"},
	{DashboardKind, "watchtowerdashboards", "Dashboard"},
}

// AsCodeResource is one as-code CR as read from the cluster.
type AsCodeResource struct {
	Kind      AsCodeKind
	Name      string
	Namespace string
	Spec      map[string]any
	Status    AsCodeStatus
}

// AsCodeStatus is what the reconciler reports: one Ready condition and the hash of the applied spec.
type AsCodeStatus struct {
	ObservedHash string      `json:"observedHash,omitempty"`
	Conditions   []Condition `json:"conditions,omitempty"`
}
