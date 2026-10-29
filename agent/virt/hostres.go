package virt

import (
	"os"
	"strings"
)

// hypervisorHost returns the host resource for a hypervisor named name. When it is the agent's
// own host, the result is just the agent's own host.name (same identity keys as the agent's
// resource, so the host entity cannot flap) and own is true. Otherwise the agent's host.id and
// os.type are blanked: they describe the agent's machine, never the hypervisor.
func hypervisorHost(name string) (res map[string]string, own bool) {
	if h, err := os.Hostname(); err == nil && h != "" {
		short := func(s string) string { return strings.ToLower(strings.SplitN(s, ".", 2)[0]) }
		if strings.EqualFold(h, name) || !strings.Contains(h, ".") && short(h) == short(name) {
			return map[string]string{"host.name": h}, true
		}
	}
	return map[string]string{"host.name": name, "host.id": "", "os.type": ""}, false
}
