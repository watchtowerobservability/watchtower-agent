package ascode

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// bundleKeys maps the top-level sections of a watchtower.yaml onto manifest kinds. A section is a
// list of resources, each `{name: ..., <spec fields>}` (a mapping keyed by name works too), except
// `routing`, which is the tree itself.
var bundleKeys = map[string]string{
	"monitors": "Monitor", "slos": "Slo", "services": "ServiceCatalog", "alert_rules": "AlertRule",
	"routing": "Routing", "receivers": "Receiver", "maintenance_windows": "MaintenanceWindow",
	"dashboards": "Dashboard", "quality_gates": "QualityGate", "environments": "Environment",
	"templates": "Template", "time_intervals": "TimeInterval", "escalation_policies": "EscalationPolicy",
	"schedules": "Schedule", "inhibit_rules": "InhibitRule", "workflows": "Workflow",
	"incident_types": "IncidentType", "security_rules": "SecurityRule", "agent_configs": "AgentConfig", "pipelines": "Pipeline", "shaping_rules": "ShapingRule",
}

// expandBundle turns a watchtower.yaml document (no `kind`, only bundle sections) into manifests.
// ok is false for an ordinary manifest document.
func expandBundle(n *yaml.Node) (docs []Doc, ok bool, err error) {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil, false, nil
	}
	var top map[string]any
	if err := n.Decode(&top); err != nil {
		return nil, false, err
	}
	if _, isManifest := top["kind"]; isManifest {
		return nil, false, nil
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		kind, known := bundleKeys[key]
		if !known {
			if key == "version" || key == "apiVersion" {
				continue
			}
			return nil, false, fmt.Errorf("watchtower.yaml: unknown section %q", key)
		}
		if kind == "Routing" {
			m, isMap := top[key].(map[string]any)
			if !isMap {
				return nil, false, fmt.Errorf("watchtower.yaml: routing must be the routing tree")
			}
			docs = append(docs, Doc{APIVersion: APIVersion, Kind: kind, Metadata: Metadata{Name: "routing"}, Spec: m})
			continue
		}
		items, err := sectionItems(key, top[key])
		if err != nil {
			return nil, false, err
		}
		k := ByKind(kind)
		for _, it := range items {
			name, _ := it[k.NameKey()].(string)
			if name == "" {
				name, _ = it["name"].(string)
			}
			delete(it, "name")
			if k.NameKey() != "name" {
				delete(it, k.NameKey())
			}
			docs = append(docs, Doc{APIVersion: APIVersion, Kind: kind, Metadata: Metadata{Name: name}, Spec: it})
		}
	}
	return docs, true, nil
}

func sectionItems(key string, v any) ([]map[string]any, error) {
	var out []map[string]any
	switch t := v.(type) {
	case nil:
	case []any:
		for i, e := range t {
			m, isMap := e.(map[string]any)
			if !isMap {
				return nil, fmt.Errorf("watchtower.yaml: %s[%d] must be a mapping", key, i)
			}
			out = append(out, m)
		}
	case map[string]any: // name -> body
		names := make([]string, 0, len(t))
		for nm := range t {
			names = append(names, nm)
		}
		sort.Strings(names)
		for _, nm := range names {
			m, _ := t[nm].(map[string]any)
			if m == nil {
				m = map[string]any{}
			}
			m["name"] = nm
			out = append(out, m)
		}
	default:
		return nil, fmt.Errorf("watchtower.yaml: %s must be a list", key)
	}
	return out, nil
}
