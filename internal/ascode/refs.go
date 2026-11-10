package ascode

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Ref makes one spec field a reference by name: a manifest says `env: production` and apply writes
// the live id of Environment/production into the body (B4). Targets applied earlier in the same run
// are known from their create response; others from the live listing the plan already fetched.
type Ref struct {
	From string // dotted path of the spec field that holds a metadata.name
	To   string // dotted path the id is written to; empty = From (replace in place)
	Kind string // kind of the target
	// Tree names the list of child nodes (`routes`) that repeat the same field, to any depth: From is
	// then a plain field of the root and of every descendant.
	Tree string
}

// treeNodes returns root and every descendant reached through the list field tree.
func treeNodes(root map[string]any, tree string) []map[string]any {
	out := []map[string]any{root}
	kids, _ := root[tree].([]any)
	for _, el := range kids {
		if m, ok := el.(map[string]any); ok {
			out = append(out, treeNodes(m, tree)...)
		}
	}
	return out
}

func (r Ref) to() string {
	if r.To == "" {
		return r.From
	}
	return r.To
}

func splitPath(p string) []string { return strings.Split(p, ".") }

func getPath(m map[string]any, p string) (any, bool) {
	var cur any = m
	for _, s := range splitPath(p) {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[s]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func setPath(m map[string]any, p string, v any) {
	parts := splitPath(p)
	for _, s := range parts[:len(parts)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[s] = next
		}
		m = next
	}
	m[parts[len(parts)-1]] = v
}

func delPath(m map[string]any, p string) {
	parts := splitPath(p)
	for _, s := range parts[:len(parts)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			return
		}
		m = next
	}
	delete(m, parts[len(parts)-1])
}

// cloneSpec deep-copies a normalized (JSON-shaped) spec.
func cloneSpec(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

// cloneValue deep-copies maps and lists, so resolving refs in nested routes never edits the input.
func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneSpec(t)
	case []any:
		out := make([]any, len(t))
		for i, el := range t {
			out[i] = cloneValue(el)
		}
		return out
	}
	return v
}

// resolveRefs returns a copy of spec with the kind's references replaced by ids. A reference that
// cannot be resolved is an error with strict, and otherwise dropped from the copy (a plan compares
// the rest; the target does not exist yet).
func (c *Client) resolveRefs(k *Kind, spec map[string]any, strict bool) (map[string]any, error) {
	out := cloneSpec(spec)
	for _, r := range k.Refs {
		if r.Tree != "" {
			for _, n := range treeNodes(out, r.Tree) {
				if n[r.From] == nil {
					continue
				}
				if err := c.swapRef(n, r.From, r.to(), r, strict); err != nil {
					return nil, err
				}
			}
			continue
		}
		if pre, leaf, ok := strings.Cut(r.From, "[]."); ok { // rules[].contact_method: every element of a list
			to := strings.TrimPrefix(r.to(), pre+"[].")
			arr, _ := getPath(out, pre)
			list, _ := arr.([]any)
			for _, el := range list {
				if m, ok := el.(map[string]any); ok {
					if err := c.swapRef(m, leaf, to, r, strict); err != nil {
						return nil, err
					}
				}
			}
			continue
		}
		v, ok := getPath(out, r.From)
		if !ok {
			continue
		}
		name, _ := v.(string)
		id, known := c.ids[r.Kind+"/"+name]
		switch {
		case name == "":
			return nil, fmt.Errorf("%s must be the name of a %s", r.From, r.Kind)
		case !known && strict:
			return nil, fmt.Errorf("%s: no %s named %q (declare it in the manifests or create it first)", r.From, r.Kind, name)
		}
		delPath(out, r.From)
		if known {
			setPath(out, r.to(), id)
		}
	}
	return out, nil
}

// refTargets lists the "Kind/name" every reference of the spec points at.
func refTargets(k *Kind, spec map[string]any) (out []string) {
	for _, r := range k.Refs {
		if r.Tree != "" {
			for _, n := range treeNodes(spec, r.Tree) {
				if s, _ := n[r.From].(string); s != "" {
					out = append(out, r.Kind+"/"+s)
				}
			}
			continue
		}
		if pre, leaf, ok := strings.Cut(r.From, "[]."); ok {
			arr, _ := getPath(spec, pre)
			list, _ := arr.([]any)
			for _, el := range list {
				if m, ok := el.(map[string]any); ok {
					if n, _ := m[leaf].(string); n != "" {
						out = append(out, r.Kind+"/"+n)
					}
				}
			}
		} else if v, ok := getPath(spec, r.From); ok {
			if n, _ := v.(string); n != "" {
				out = append(out, r.Kind+"/"+n)
			}
		}
	}
	return out
}

// swapRef replaces m[leaf] (a name) by the id of the named resource, written to m[to].
func (c *Client) swapRef(m map[string]any, leaf, to string, r Ref, strict bool) error {
	v, ok := m[leaf]
	if !ok {
		return nil
	}
	name, _ := v.(string)
	id, known := c.ids[r.Kind+"/"+name]
	switch {
	case name == "":
		return fmt.Errorf("%s must be the name of a %s", r.From, r.Kind)
	case !known && strict:
		return fmt.Errorf("%s: no %s named %q (declare it in the manifests or create it first)", r.From, r.Kind, name)
	}
	delete(m, leaf)
	if known {
		m[to] = id
	}
	return nil
}

// remember records the id of a live or just-created resource for later references.
func (c *Client) remember(kind, name, id string) {
	if id == "" {
		return
	}
	if c.ids == nil {
		c.ids = map[string]string{}
	}
	c.ids[kind+"/"+name] = id
}

// localSpec removes the fields that only steer wtctl (never sent to the API, never compared).
func localSpec(k *Kind, spec map[string]any) map[string]any {
	if len(k.LocalFields) == 0 {
		return spec
	}
	out := make(map[string]any, len(spec))
	for f, v := range spec {
		out[f] = v
	}
	for _, f := range k.LocalFields {
		delete(out, f)
	}
	return out
}

var tokenEnvChars = regexp.MustCompile(`[^A-Za-z0-9]+`)

// saveToken appends the one-time secret of a created resource to the spec's write_token_to file
// (mode 0600, as NAME=value, the name from token_env or WT_<KIND>_<NAME>) before anything else can
// fail. Nothing to do without write_token_to or without a secret in the response.
func saveToken(k *Kind, name string, spec, out map[string]any) error {
	path, _ := spec["write_token_to"].(string)
	if path == "" {
		return nil
	}
	secret := k.SecretOut
	if secret == "" {
		secret = "token"
	}
	tok, _ := out[secret].(string)
	if tok == "" {
		return nil
	}
	v, _ := spec["token_env"].(string)
	if v == "" {
		v = strings.ToUpper(tokenEnvChars.ReplaceAllString("WT_"+k.Name+"_"+name, "_"))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s=%s\n", v, tok); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
