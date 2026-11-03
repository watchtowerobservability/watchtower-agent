// Package ascode is the configuration-as-code engine shared by `wtctl apply|diff|export` and the
// Terraform provider: manifests of kind X named N in project P map onto the project REST API.
package ascode

import (
	"context"
	"sort"
)

// APIVersion is the only manifest apiVersion.
const APIVersion = "watchtower.dev/v1"

// Kind describes how one resource kind maps onto the API below /v1/projects/{prj}/.
type Kind struct {
	Name   string // manifest kind
	Path   string // collection path
	Key    string // body field that carries metadata.name (default "name")
	Update string // method for in-place updates on the item path (default PUT)

	ByName    bool // the item path uses the name, and PUT creates (no POST, no server id)
	NoList    bool // the API cannot list; every apply is sent and the server reports "unchanged"
	Singleton bool // one document per project at Path (GET and PUT, no delete)
	// CreateOnly kinds are never updated or compared once they exist (the secret is shown once).
	CreateOnly bool
	// SecretFields are body fields (or, for a map, all its values) that may only be ${ENV} references.
	SecretFields []string
	NoPrune      bool
	// Versioned kinds list summaries only and update under optimistic locking: List fetches each
	// item for its full body, and Update sends If-Match with the live version.
	Versioned bool
	// UpdateOmit are body fields the update endpoint rejects (they are only valid on create).
	UpdateOmit []string
	// NoBodyName keeps the name out of the request body (the path carries it and the schema is closed).
	NoBodyName bool
	// Org kinds live below /v1/orgs/{org}/ (Path is absolute with an {org} placeholder; Client.Org fills it).
	Org bool
	// IntKey: Key names an integer body field (a retention rule is identified by its priority).
	IntKey bool
	// NoDelete kinds cannot be deleted through the API; removing them only forgets them.
	NoDelete bool
	// ResetOnDelete, when set, is PUT to the item instead of DELETE (an IP allowlist is reset, not removed).
	ResetOnDelete map[string]any
	// SecretOut is the response field that carries the one-time secret (default "token").
	SecretOut string

	// ops replaces the generic REST mapping for kinds that are not one document per resource
	// (a Pipeline is a resource plus versions).
	ops kindOps
}

// kindOps is the custom list/create/update/delete of a kind.
type kindOps interface {
	list(ctx context.Context, c *Client) (map[string]Item, error)
	create(ctx context.Context, c *Client, name string, spec map[string]any) (map[string]any, error)
	update(ctx context.Context, c *Client, it Item, name string, spec map[string]any) (map[string]any, error)
	remove(ctx context.Context, c *Client, it Item) error
}

// Kinds lists every supported resource kind, in apply order.
var Kinds = []*Kind{
	{Name: "Template", Path: "templates", Update: "PATCH"},
	{Name: "Receiver", Path: "receivers", SecretFields: []string{"secrets"}},
	{Name: "TimeInterval", Path: "time-intervals", UpdateOmit: []string{"name"}},
	{Name: "Routing", Path: "routing", Singleton: true, NoPrune: true},
	{Name: "InhibitRule", Path: "inhibit-rules"},
	{Name: "AlertRule", Path: "alert-rules"},
	{Name: "RuleGroup", Path: "rule-groups", ByName: true, NoList: true, NoPrune: true},
	{Name: "LokiRuleGroup", Path: "loki/api/v1/rules", ops: lokiRuleOps{}}, // name: <namespace>/<group>
	{Name: "MaintenanceWindow", Path: "maintenance-windows"},
	{Name: "Silence", Path: "silences", Key: "comment"}, // a silence has no name: its comment is the identity
	{Name: "Slo", Path: "slos"},
	{Name: "Monitor", Path: "monitors"},
	{Name: "CheckSecret", Path: "check-secrets", ByName: true, CreateOnly: true, SecretFields: []string{"value"}},
	{Name: "Schedule", Path: "oncall/schedules"},
	{Name: "EscalationPolicy", Path: "escalation-policies"},
	{Name: "IncidentType", Path: "incident-types"},
	{Name: "Workflow", Path: "workflows"},
	{Name: "Dashboard", Path: "dashboards", Key: "title", Versioned: true, UpdateOmit: []string{"kind"}},
	{Name: "ServiceCatalog", Path: "catalog/services", Key: "service", ByName: true, NoPrune: true},
	{Name: "AgentConfig", Path: "agent-configs"},
	{Name: "Pipeline", Path: "pipelines", ops: pipelineOps{}},
	{Name: "AttributeRegistry", Path: "attribute-registry", Key: "key", Update: "PATCH", UpdateOmit: []string{"signal", "key"}},
	{Name: "ArchiveConfig", Path: "archive", ByName: true, NoList: true, NoPrune: true, NoBodyName: true, SecretFields: []string{"credentials"}},
	{Name: "FleetConfig", Path: "fleet/configs", CreateOnly: true, NoDelete: true}, // no DELETE route: G6-12
	{Name: "RetentionRule", Path: "retention-rules", Key: "priority", IntKey: true},
	{Name: "ChangeSource", Path: "change-sources", Key: "kind", CreateOnly: true, SecretOut: "secret"}, // one source per provider kind
	// One schedule per signal: the body has no name, so the signal is the identity (G6-12).
	{Name: "ExportSchedule", Path: "export-schedules", Key: "signal", Update: "PATCH",
		UpdateOmit: []string{"signal", "dest_kind", "format"}, SecretFields: []string{"credentials"}},
	{Name: "IpAllowlist", Path: "/v1/orgs/{org}/ip-allowlists", Org: true, ByName: true, NoList: true, NoPrune: true, NoBodyName: true,
		ResetOnDelete: map[string]any{"cidrs": []string{}, "enabled": false}}, // name = scope: org, api_keys, ingest, sessions
	{Name: "OrgSso", Path: "/v1/orgs/{org}/sso", Org: true, Singleton: true, NoPrune: true},
	{Name: "SecretStore", Path: "/v1/orgs/{org}/secret-stores", Org: true, CreateOnly: true, SecretFields: []string{"credential"}},
	{Name: "HealthToken", Path: "health-tokens", CreateOnly: true},
}

// ByKind finds a kind by manifest name.
func ByKind(name string) *Kind {
	for _, k := range Kinds {
		if k.Name == name {
			return k
		}
	}
	return nil
}

// KindNames is the sorted list of kind names.
func KindNames() []string {
	var n []string
	for _, k := range Kinds {
		n = append(n, k.Name)
	}
	sort.Strings(n)
	return n
}

// NameKey is the body field that holds the resource name.
func (k *Kind) NameKey() string {
	if k.Key == "" {
		return "name"
	}
	return k.Key
}

func (k *Kind) updateMethod() string {
	if k.Update == "" {
		return "PUT"
	}
	return k.Update
}
