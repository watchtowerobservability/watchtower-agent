package ascode

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// serverFields are returned by the API but are not part of what a manifest declares.
var serverFields = []string{
	"id", "project_id", "org_id", "created_at", "created_by", "updated_at", "updated_by", "version",
	"has_secrets", "generated_secret", "token", "prefix", "last_used_at", "revoked_at", "active",
	"observed", "first_seen_ns", "last_seen_ns", "alerting", // alerting: the read-only delivery readiness on rules and monitors
	"next_eval_at", "groups_truncated", "warnings", // alert rules: scheduler state and create-time notes
	"muted_until", "rebuilt_at", "rebuild_error", // monitors (mute state) and schedules (rebuild state)
}

// Export reads the live resources of the kinds (all when empty) as manifests. Secret fields become
// ${ENV} references; values are never read or written.
func (c *Client) Export(ctx context.Context, kinds []string) ([]Doc, error) {
	var ks []*Kind
	if len(kinds) == 0 {
		for _, k := range Kinds {
			if k.Name != "ContactMethod" { // the exporter's own addresses are not the project's configuration
				ks = append(ks, k)
			}
		}
	}
	for _, n := range kinds {
		k := ByKind(n)
		if k == nil {
			return nil, fmt.Errorf("unknown kind %q (known: %s)", n, strings.Join(KindNames(), ", "))
		}
		ks = append(ks, k)
	}
	var docs []Doc
	names := map[string]map[string]string{} // target kind -> id -> name, for turning ids back into references
	for _, k := range ks {
		items, err := c.List(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", k.Name, err)
		}
		order := make([]string, 0, len(items))
		for n := range items {
			order = append(order, n)
		}
		sort.Strings(order)
		for _, n := range order {
			d := ExportDoc(k, n, items[n].Body)
			if err := c.nameRefs(ctx, k, d.Spec, names); err != nil {
				return nil, err
			}
			docs = append(docs, d)
		}
	}
	return docs, nil
}

// ExportDoc turns a live body into a manifest.
func ExportDoc(k *Kind, name string, body map[string]any) Doc {
	if k.Singleton && name == "" {
		name = strings.ToLower(k.Name) // one document per project: the kind names it (routing, orgsso)
	}
	spec := map[string]any{}
	for f, v := range body {
		spec[f] = v
	}
	delete(spec, k.NameKey())
	if !k.Singleton { // a routing tree's own `id` is part of the tree
		for _, f := range serverFields {
			delete(spec, f)
		}
	}
	for _, f := range k.ExportOmit {
		delete(spec, f)
	}
	for _, f := range k.SecretFields {
		switch v := spec[f].(type) {
		case map[string]any:
			for sub := range v {
				v[sub] = envName(k, name, f+"_"+sub)
			}
		default:
			if _, ok := body[f]; ok || k.CreateOnly {
				spec[f] = envName(k, name, f)
			}
		}
	}
	return Doc{APIVersion: APIVersion, Kind: k.Name, Metadata: Metadata{Name: name}, Spec: spec}
}

var nonEnv = regexp.MustCompile(`[^A-Z0-9]+`)

func envName(k *Kind, name, field string) string {
	return "${WT_" + strings.Trim(nonEnv.ReplaceAllString(strings.ToUpper(k.Name+"_"+name+"_"+field), "_"), "_") + "}"
}

// Marshal renders manifests as a multi-document YAML stream.
func Marshal(docs []Doc) ([]byte, error) {
	var sb strings.Builder
	for i, d := range docs {
		if i > 0 {
			sb.WriteString("---\n")
		}
		b, err := yaml.Marshal(d)
		if err != nil {
			return nil, err
		}
		sb.Write(b)
	}
	return []byte(sb.String()), nil
}

// nameRefs turns the ids a kind's references hold (env_id) back into the target's name (env), the
// form a manifest uses; an id that is not found stays as it is.
func (c *Client) nameRefs(ctx context.Context, k *Kind, spec map[string]any, cache map[string]map[string]string) error {
	for _, r := range k.Refs {
		if cache[r.Kind] == nil {
			items, err := c.List(ctx, ByKind(r.Kind))
			if err != nil {
				return fmt.Errorf("list %s: %w", r.Kind, err)
			}
			cache[r.Kind] = map[string]string{}
			for n, it := range items {
				cache[r.Kind][it.Ref] = n
			}
		}
		swap := func(m map[string]any, from, to string) {
			if id, _ := m[to].(string); id != "" && cache[r.Kind][id] != "" {
				delete(m, to)
				m[from] = cache[r.Kind][id]
			}
		}
		if r.Tree != "" {
			for _, n := range treeNodes(spec, r.Tree) {
				swap(n, r.From, r.to())
			}
			continue
		}
		if pre, leaf, ok := strings.Cut(r.From, "[]."); ok {
			arr, _ := getPath(spec, pre)
			list, _ := arr.([]any)
			for _, el := range list {
				if m, ok := el.(map[string]any); ok {
					swap(m, leaf, strings.TrimPrefix(r.to(), pre+"[]."))
				}
			}
			continue
		}
		if id, _ := getPath(spec, r.to()); id != nil {
			if s, _ := id.(string); cache[r.Kind][s] != "" {
				delPath(spec, r.to())
				setPath(spec, r.From, cache[r.Kind][s])
			}
		}
	}
	return nil
}
