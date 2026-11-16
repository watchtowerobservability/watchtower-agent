package container

import (
	"path"
	"strings"
)

// CgroupFilter selects which container cgroups the socket-free scan reports. The zero value
// reports all of them. Paths are relative to the cgroup root with a leading "/", e.g.
// /system.slice/docker-<id>.scope or /wt-myapp.slice/docker-<id>.scope.
type CgroupFilter struct {
	// Parent keeps only cgroups under a directory of this name (a systemd slice "wt-x.slice" or a
	// cgroupfs path "/wt-x"): the `cgroup_parent` of the compose services.
	Parent string
	// Include (when non-empty) and Exclude are path.Match globs on the cgroup path and on the
	// container name when one is known. `*` does not cross `/`.
	Include, Exclude []string
	// IDs (when non-nil) keeps only these container ids (the engine's matched containers).
	IDs map[string]bool
	// Labels (when set) keeps only containers whose learned labels (from forwarded logs) match;
	// a container nothing is learned about yet is skipped, never reported by default.
	Labels LabelSet
}

func matchAny(pats []string, subjects ...string) bool {
	for _, p := range pats {
		for _, s := range subjects {
			if s == "" {
				continue
			}
			if ok, _ := path.Match(p, s); ok {
				return true
			}
		}
	}
	return false
}

// Match reports whether the cgroup at cgPath (container id, name when known) is reported.
func (f *CgroupFilter) Match(cgPath, id, name string, labels map[string]string) bool {
	if f == nil {
		return true
	}
	if f.IDs != nil && !f.IDs[id] {
		return false
	}
	if p := strings.Trim(f.Parent, "/"); p != "" && !strings.Contains(cgPath+"/", "/"+p+"/") {
		return false
	}
	if len(f.Labels) > 0 && !HasLabels(labels, f.Labels) {
		return false
	}
	if len(f.Include) > 0 && !matchAny(f.Include, cgPath, name) {
		return false
	}
	return !matchAny(f.Exclude, cgPath, name)
}
