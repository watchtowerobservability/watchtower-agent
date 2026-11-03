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
	"observed", "first_seen_ns", "last_seen_ns",
}

// Export reads the live resources of the kinds (all when empty) as manifests. Secret fields become
// ${ENV} references; values are never read or written.
func (c *Client) Export(ctx context.Context, kinds []string) ([]Doc, error) {
	var ks []*Kind
	if len(kinds) == 0 {
		ks = Kinds
	}
	for _, n := range kinds {
		k := ByKind(n)
		if k == nil {
			return nil, fmt.Errorf("unknown kind %q (known: %s)", n, strings.Join(KindNames(), ", "))
		}
		ks = append(ks, k)
	}
	var docs []Doc
	for _, k := range ks {
		items, err := c.List(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", k.Name, err)
		}
		names := make([]string, 0, len(items))
		for n := range items {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			docs = append(docs, ExportDoc(k, n, items[n].Body))
		}
	}
	return docs, nil
}

// ExportDoc turns a live body into a manifest.
func ExportDoc(k *Kind, name string, body map[string]any) Doc {
	if k.Singleton && name == "" {
		name = "routing"
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
