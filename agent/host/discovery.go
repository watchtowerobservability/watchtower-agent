package host

import (
	"fmt"
	"path"
)

// Kinds that low-level discovery can enumerate.
const (
	KindFilesystem = "filesystem"
	KindDisk       = "disk"
	KindNIC        = "nic"
	KindGPU        = "gpu"
)

// Rule is one low-level discovery rule (INF-020). Include and Exclude are path.Match globs
// against the child's name (mount point, device, interface or GPU index). No include means all;
// exclude wins.
type Rule struct {
	Kind    string   `json:"kind"`
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// Discovery is the list of rules. A kind without a rule is collected whole.
type Discovery []Rule

// Validate checks kinds and patterns.
func (d Discovery) Validate() error {
	if len(d) > 20 {
		return fmt.Errorf("at most 20 discovery rules")
	}
	for _, r := range d {
		switch r.Kind {
		case KindFilesystem, KindDisk, KindNIC, KindGPU:
		default:
			return fmt.Errorf("discovery kind %q: want filesystem, disk, nic or gpu", r.Kind)
		}
		for _, p := range append(append([]string{}, r.Include...), r.Exclude...) {
			if _, err := path.Match(p, ""); err != nil {
				return fmt.Errorf("discovery pattern %q: %w", p, err)
			}
		}
	}
	return nil
}

// Allow reports whether the child called name of kind is collected.
func (d Discovery) Allow(kind, name string) bool {
	ruled, ok := false, false
	for _, r := range d {
		if r.Kind != kind {
			continue
		}
		ruled = true
		if matchAny(r.Exclude, name) {
			return false
		}
		if len(r.Include) == 0 || matchAny(r.Include, name) {
			ok = true
		}
	}
	return ok || !ruled
}

// Children returns the names of kind that the rules let through, in order.
func (d Discovery) Children(kind string, names []string) []string {
	var out []string
	for _, n := range names {
		if d.Allow(kind, n) {
			out = append(out, n)
		}
	}
	return out
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}
