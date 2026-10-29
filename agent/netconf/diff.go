package netconf

import (
	"fmt"
	"strings"
)

const diffContext = 3

// Unified returns a line-based unified diff of two configs (LCS), empty when equal. It matches
// the API's diff output so the CLI and the UI agree.
func Unified(oldCfg, newCfg string, from, to int) string {
	a := strings.Split(strings.TrimSuffix(oldCfg, "\n"), "\n")
	b := strings.Split(strings.TrimSuffix(newCfg, "\n"), "\n")
	w := len(b) + 1
	lcs := make([]int, (len(a)+1)*w)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else {
				lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
			}
		}
	}
	type op struct {
		c        byte
		text     string
		old, new int
	}
	var ops []op
	for i, j := 0, 0; i < len(a) || j < len(b); {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], i + 1, j + 1})
			i++
			j++
		case j < len(b) && (i == len(a) || lcs[i*w+j+1] > lcs[(i+1)*w+j]):
			ops = append(ops, op{'+', b[j], i + 1, j + 1})
			j++
		default:
			ops = append(ops, op{'-', a[i], i + 1, j + 1})
			i++
		}
	}
	var changed []int
	for k, o := range ops {
		if o.c != ' ' {
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- v%d\n+++ v%d\n", from, to)
	for k := 0; k < len(changed); {
		start := max(changed[k]-diffContext, 0)
		end := changed[k]
		for k < len(changed) && changed[k] <= end+2*diffContext+1 {
			end = changed[k]
			k++
		}
		end = min(end+diffContext+1, len(ops))
		hunk := ops[start:end]
		on, nn := 0, 0
		for _, o := range hunk {
			if o.c != '+' {
				on++
			}
			if o.c != '-' {
				nn++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", hunk[0].old, on, hunk[0].new, nn)
		for _, o := range hunk {
			out.WriteByte(o.c)
			out.WriteString(o.text)
			out.WriteByte('\n')
		}
	}
	return out.String()
}
