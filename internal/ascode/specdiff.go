package ascode

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// MaxDiffLines caps a rendered spec diff (a pull request body stays readable).
const MaxDiffLines = 200

// SpecDiff is the semantic difference of two specs: one line per changed leaf, with list items
// compared by position and named by their `title` (panels) or `name` when they have one, so a
// reviewer reads "panels[2 "Latency"].targets[0].expr: ... -> ..." instead of a YAML text diff.
func SpecDiff(old, cur map[string]any) []string {
	var out []string
	diffAny(old, cur, "", &out)
	return out
}

func diffAny(a, b any, path string, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			diffAny(am[k], bm[k], join(path, k), out)
		}
		return
	}
	al, alok := a.([]any)
	bl, blok := b.([]any)
	if alok && blok {
		for i := 0; i < len(al) || i < len(bl); i++ {
			switch {
			case i >= len(al):
				*out = append(*out, fmt.Sprintf("%s added: %s", item(path, i, bl[i]), short(bl[i])))
			case i >= len(bl):
				*out = append(*out, fmt.Sprintf("%s removed", item(path, i, al[i])))
			default:
				diffAny(al[i], bl[i], item(path, i, bl[i]), out)
			}
		}
		return
	}
	if !reflect.DeepEqual(a, b) {
		*out = append(*out, fmt.Sprintf("%s: %s -> %s", orRoot(path), short(a), short(b)))
	}
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func orRoot(p string) string {
	if p == "" {
		return "spec"
	}
	return p
}

func item(path string, i int, v any) string {
	if m, ok := v.(map[string]any); ok {
		for _, f := range []string{"title", "name"} {
			if s, ok := m[f].(string); ok && s != "" {
				return fmt.Sprintf("%s[%d %q]", path, i, s)
			}
		}
	}
	return fmt.Sprintf("%s[%d]", path, i)
}

// RenderSpecDiff is the Markdown block for a pull request body or comment.
func RenderSpecDiff(kind, name string, lines []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**%s `%s`**", kind, name)
	if len(lines) == 0 {
		sb.WriteString(": no semantic change\n")
		return sb.String()
	}
	sb.WriteString("\n\n```\n")
	for i, l := range lines {
		if i == MaxDiffLines {
			fmt.Fprintf(&sb, "... %d more\n", len(lines)-i)
			break
		}
		sb.WriteString(strings.ReplaceAll(l, "```", "'''") + "\n")
	}
	sb.WriteString("```\n")
	return sb.String()
}
