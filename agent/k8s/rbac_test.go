package k8s

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
	"github.com/watchtowerobservability/watchtower-agent/internal/repofile"

	"gopkg.in/yaml.v3"
)

type rule struct {
	APIGroups     []string `yaml:"apiGroups"`
	Resources     []string `yaml:"resources"`
	ResourceNames []string `yaml:"resourceNames"`
	Verbs         []string `yaml:"verbs"`
}

type doc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Rules []rule `yaml:"rules"`
}

func TestRBACHasNoSecretsAccess(t *testing.T) {
	b, err := os.ReadFile(repofile.Path("infra/kubernetes/agent/rbac.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	roles := 0
	for {
		var d doc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		for _, r := range d.Rules {
			for _, res := range r.Resources {
				switch res {
				case "secrets", "*", "pods/exec", "pods/attach", "pods/portforward", "configmaps", "nodes/proxy", "serviceaccounts/token":
					t.Errorf("%s %s: must not grant %q", d.Kind, d.Metadata.Name, res)
				}
			}
			if slices.Contains(r.APIGroups, "*") || slices.Contains(r.Verbs, "*") {
				t.Errorf("%s %s: wildcards are not allowed", d.Kind, d.Metadata.Name)
			}
		}
		switch d.Kind {
		case "ClusterRole":
			roles++
			for _, r := range d.Rules {
				for _, v := range r.Verbs {
					if v != "get" && v != "list" && v != "watch" {
						t.Errorf("ClusterRole %s: verb %q is not read-only", d.Metadata.Name, v)
					}
				}
			}
		case "Role":
			roles++
			// The only write: update the one named leader Lease.
			for _, r := range d.Rules {
				if !slices.Equal(r.Resources, []string{"leases"}) || len(r.ResourceNames) != 1 {
					t.Errorf("Role %s: only a named lease is allowed, got %+v", d.Metadata.Name, r)
				}
				for _, v := range r.Verbs {
					if v != "get" && v != "update" {
						t.Errorf("Role %s: verb %q on the lease", d.Metadata.Name, v)
					}
				}
			}
		}
	}
	if roles != 3 {
		t.Fatalf("expected two ClusterRoles and one Role, saw %d", roles)
	}
}
