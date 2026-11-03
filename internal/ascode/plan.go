package ascode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// Operations of a Change.
const (
	OpCreate = "create"
	OpUpdate = "update"
	OpDelete = "delete"
	OpNoop   = "noop"
	OpApply  = "apply" // RuleGroup: the API cannot list, so only the PUT reveals whether anything changed
)

// Change is one planned (or applied) step.
type Change struct {
	Op     string
	Kind   string
	Name   string
	Fields []string // "field: live -> wanted" lines for updates

	doc  *Doc
	live Item
}

// Changed reports whether the step is known to write something (a RuleGroup is resolved by its PUT).
func (c Change) Changed() bool { return c.Op != OpNoop && c.Op != OpApply }

func (c Change) String() string {
	sym := map[string]string{OpCreate: "+", OpUpdate: "~", OpDelete: "-", OpNoop: "=", OpApply: "?"}[c.Op]
	s := fmt.Sprintf("%s %s/%s", sym, c.Kind, c.Name)
	for _, f := range c.Fields {
		s += "\n    " + f
	}
	return s
}

// Plan compares the manifests with the live project. With prune, live resources of the manifests'
// kinds that no manifest names are planned for deletion.
func (c *Client) Plan(ctx context.Context, docs []Doc, prune bool) ([]Change, error) {
	docs = slices.Clone(docs)
	sort.SliceStable(docs, func(i, j int) bool { return kindRank(docs[i].Kind) < kindRank(docs[j].Kind) })
	live := map[string]map[string]Item{}
	var out []Change
	want := map[string]bool{}
	for i := range docs {
		d := &docs[i]
		k := ByKind(d.Kind)
		if live[k.Name] == nil {
			items, err := c.List(ctx, k)
			if err != nil {
				return nil, fmt.Errorf("list %s: %w", k.Name, err)
			}
			live[k.Name] = items
		}
		want[d.Kind+"/"+d.Metadata.Name] = true
		key := d.Metadata.Name
		if k.Singleton {
			key = ""
		}
		it, ok := live[k.Name][key]
		ch := Change{Kind: k.Name, Name: d.Metadata.Name, doc: d, live: it}
		switch {
		case k.NoList:
			ch.Op = OpApply
		case !ok:
			ch.Op = OpCreate
		case k.CreateOnly:
			ch.Op = OpNoop
		default:
			ch.Fields = subsetDiff(withoutSecrets(k, d.Spec), it.Body, "")
			ch.Op = OpNoop
			if len(ch.Fields) > 0 {
				ch.Op = OpUpdate
			}
		}
		out = append(out, ch)
	}
	if prune {
		for _, k := range Kinds {
			items, ok := live[k.Name]
			if !ok || k.NoPrune {
				continue
			}
			var names []string
			for n := range items {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if !want[k.Name+"/"+n] {
					out = append(out, Change{Op: OpDelete, Kind: k.Name, Name: n, live: items[n]})
				}
			}
		}
	}
	return out, nil
}

func kindRank(name string) int {
	for i, k := range Kinds {
		if k.Name == name {
			return i
		}
	}
	return len(Kinds)
}

// Apply executes a plan. Secrets the API shows once (health token, generated webhook secret) go to
// secrets. With dry set nothing is written. It returns the plan with RuleGroup steps resolved.
func (c *Client) Apply(ctx context.Context, plan []Change, dry bool, secrets io.Writer) ([]Change, error) {
	res := make([]Change, 0, len(plan))
	for _, ch := range plan {
		k := ByKind(ch.Kind)
		if dry || ch.Op == OpNoop {
			res = append(res, ch)
			continue
		}
		var out map[string]any
		var err error
		switch ch.Op {
		case OpDelete:
			err = c.Delete(ctx, k, ch.live)
		case OpCreate, OpUpdate, OpApply:
			var spec map[string]any
			if spec, err = ExpandSecrets(k, ch.doc.Spec); err != nil {
				return res, fmt.Errorf("%s/%s: %w", ch.Kind, ch.Name, err)
			}
			if ch.Op == OpUpdate {
				out, err = c.Update(ctx, k, ch.live, ch.Name, spec)
			} else {
				out, err = c.Create(ctx, k, ch.Name, spec)
			}
		}
		if err != nil {
			return res, fmt.Errorf("%s %s/%s: %w", ch.Op, ch.Kind, ch.Name, err)
		}
		if ch.Op == OpApply {
			if u, _ := out["unchanged"].(bool); u {
				ch.Op = OpNoop
			} else {
				ch.Op = OpUpdate
			}
		}
		ShowOnce(secrets, ch.Kind, ch.Name, out)
		res = append(res, ch)
	}
	return res, nil
}

// ShowOnce prints the secrets of a create response to w; they are never stored or shown again.
func ShowOnce(w io.Writer, kind, name string, out map[string]any) {
	if w == nil {
		return
	}
	for _, f := range []string{"token", "generated_secret"} {
		if s, _ := out[f].(string); s != "" {
			fmt.Fprintf(w, "%s/%s: %s %s (shown once; store it now)\n", kind, name, f, s)
		}
	}
}

// Count returns how many steps write something.
func Count(plan []Change) (n int) {
	for _, c := range plan {
		if c.Changed() {
			n++
		}
	}
	return n
}

// subsetDiff lists where want (the manifest) differs from have (live). Fields the manifest does not
// mention are the server's business and never differ.
func subsetDiff(want map[string]any, have map[string]any, prefix string) (out []string) {
	keys := make([]string, 0, len(want))
	for f := range want {
		keys = append(keys, f)
	}
	sort.Strings(keys)
	for _, f := range keys {
		w, h := want[f], have[f]
		path := prefix + f
		wm, wok := w.(map[string]any)
		hm, hok := h.(map[string]any)
		switch {
		case wok && hok:
			out = append(out, subsetDiff(wm, hm, path+".")...)
		case w == nil && h == nil, reflect.DeepEqual(w, h):
		default:
			out = append(out, fmt.Sprintf("%s: %s -> %s", path, short(h), short(w)))
		}
	}
	return out
}

func short(v any) string {
	if v == nil {
		return "(unset)"
	}
	b, _ := json.Marshal(v)
	if len(b) > 80 {
		return string(b[:77]) + "..."
	}
	return string(b)
}

// Drift is the Terraform view of Plan: the changed fields of one spec against the live body.
func Drift(k *Kind, spec, live map[string]any) []string {
	return subsetDiff(withoutSecrets(k, spec), live, "")
}

// Project returns live restricted to the keys of spec (recursively), so a stored spec string can be
// refreshed without growing server-side fields.
func Project(spec, live map[string]any) map[string]any {
	out := map[string]any{}
	for f, w := range spec {
		h, ok := live[f]
		if !ok {
			continue
		}
		wm, wok := w.(map[string]any)
		hm, hok := h.(map[string]any)
		if wok && hok {
			out[f] = Project(wm, hm)
		} else {
			out[f] = h
		}
	}
	return out
}

// Summary renders a plan for humans, ending with a count line.
func Summary(plan []Change) string {
	var sb strings.Builder
	for _, c := range plan {
		if c.Op != OpNoop {
			sb.WriteString(c.String() + "\n")
		}
	}
	fmt.Fprintf(&sb, "%d change(s)\n", Count(plan))
	return sb.String()
}
