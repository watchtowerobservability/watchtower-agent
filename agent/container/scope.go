package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"
)

// ScopeSelf limits the Docker modules to the compose project of the agent's own container.
const ScopeSelf = "self"

// containersDirRE finds the id in /proc/self/mountinfo (".../containers/<id>/hostname", also
// ".../docker/containers/<id>/resolv.conf"), the source that works with cgroup namespaces.
var containersDirRE = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// SelfContainerID returns the agent's own container id from the text of /proc/self/cgroup
// (cgroup v1 "N:ctrl:/docker/<id>", v2 "0::/system.slice/docker-<id>.scope", cgroupfs or
// systemd, kubepods) or, failing that, /proc/self/mountinfo. "" when neither names one.
func SelfContainerID(cgroup, mountinfo string) string {
	for _, l := range strings.Split(cgroup, "\n") {
		p := l[strings.LastIndexByte(l, ':')+1:]
		segs := strings.Split(p, "/")
		for i := len(segs) - 1; i >= 0; i-- {
			if m := scopeRE.FindStringSubmatch(segs[i]); m != nil {
				return m[1]
			}
		}
	}
	if m := containersDirRE.FindStringSubmatch(mountinfo); m != nil {
		return m[1]
	}
	return ""
}

// SelfProject inspects only the agent's own container (by id, else by hostname, which Docker
// sets to the short id) and returns its compose project label. get is a GET-and-decode on the engine.
func SelfProject(get func(path string, v any) error, cgroup, mountinfo, hostname string) (string, error) {
	ref := SelfContainerID(cgroup, mountinfo)
	byHost := ref == ""
	if byHost {
		ref = hostname
	}
	if ref == "" || strings.ContainsAny(ref, "/?# ") {
		return "", errors.New("cannot determine the agent's own container id")
	}
	var raw struct {
		ID     string `json:"Id"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := get("/containers/"+ref+"/json", &raw); err != nil {
		return "", fmt.Errorf("inspect own container %q: %w", ref, err)
	}
	if byHost && !strings.HasPrefix(raw.ID, ref) { // a hostname may also be another container's name
		return "", fmt.Errorf("hostname %q is not the agent's own container id; mount a cgroup or /proc that names it", ref)
	}
	p := raw.Config.Labels[ComposeProjectLabel]
	if p == "" {
		return "", fmt.Errorf("own container %q has no %s label (not started by docker compose / Coolify?)", ref, ComposeProjectLabel)
	}
	return p, nil
}

// WantsSelf is true when scope (a module's `scope` key) or WT_AGENT_SCOPE asks for `self`.
// Any other non-empty value is an error, never "all".
func WantsSelf(scope string) (bool, error) {
	if scope == "" {
		scope = os.Getenv("WT_AGENT_SCOPE")
	}
	switch scope {
	case "":
		return false, nil
	case ScopeSelf:
		return true, nil
	}
	return false, fmt.Errorf("scope %q: the only value is %q", scope, ScopeSelf)
}

// ResolveSelfScope blocks until the agent's own compose project is known and returns it. It
// never returns without one except when ctx ends: scope self must not fall back to every container.
func ResolveSelfScope(ctx context.Context, module string, get func(path string, v any) error) (string, error) {
	for {
		cg, _ := os.ReadFile("/proc/self/cgroup")
		mi, _ := os.ReadFile("/proc/self/mountinfo")
		h, _ := os.Hostname()
		p, err := SelfProject(get, string(cg), string(mi), h)
		if err == nil {
			slog.Info(module+": scope self resolved", "compose_project", p)
			return p, nil
		}
		slog.Error(module+": scope self: collecting nothing until the own compose project is known", "error", err)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
}

// Get is d's GET-and-decode bound to ctx, for ResolveSelfScope.
func (d *Docker) Get(ctx context.Context) func(string, any) error {
	return func(path string, v any) error { return d.get(ctx, path, v) }
}

// ApplyScope sets labels to the own compose project when scope (or WT_AGENT_SCOPE) is self.
func ApplyScope(ctx context.Context, module, scope string, labels *LabelSet, get func(string, any) error) error {
	self, err := WantsSelf(scope)
	if err != nil || !self {
		return err
	}
	p, err := ResolveSelfScope(ctx, module, get)
	if err != nil {
		return err
	}
	if *labels == nil {
		*labels = LabelSet{}
	}
	(*labels)[ComposeProjectLabel] = []string{p}
	return nil
}

// ProjectsIn counts the distinct compose projects among cs.
func ProjectsIn(cs []Info) int {
	m := map[string]bool{}
	for _, c := range cs {
		if p := c.Labels[ComposeProjectLabel]; p != "" {
			m[p] = true
		}
	}
	return len(m)
}
