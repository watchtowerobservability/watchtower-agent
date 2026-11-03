package integrations

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/internal/repofile"
)

var manifestsDir = filepath.Dir(repofile.Path("integrations/schema.json")) // the go/agent/integrations package dir would also match "integrations"

var v1Set = []string{"activemq", "apache", "cassandra", "ceph", "clickhouse", "consul", "coredns", "couchbase", "docker", "elasticsearch", "envoy", "etcd", "gitlab", "haproxy", "host", "hyperv", "iis", "istio", "jenkins", "jmx", "kafka", "kinesis", "kong", "memcached", "milvus", "minio", "mongodb", "mssql", "mysql", "nats", "nginx", "nomad", "oracle", "pinecone", "postgres", "pulsar", "qdrant", "rabbitmq", "redis", "sap", "solr", "tomcat", "traefik", "vault", "weaviate", "windows", "zookeeper"}

func loadAll(t *testing.T) []*Manifest {
	t.Helper()
	ms, err := LoadFS(os.DirFS(manifestsDir))
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func TestManifestSchemaValidAll(t *testing.T) {
	ms := loadAll(t)
	var got []string
	for _, m := range ms {
		got = append(got, m.Name)
		if len(m.Metrics) == 0 || len(m.Alerts) == 0 || len(m.Dashboards) == 0 {
			t.Errorf("%s: metrics, alerts and dashboards must be filled", m.Name)
		}
		for _, a := range m.Alerts {
			if a.Rule["kind"] != "metric" || a.Rule["name"] != a.Name {
				t.Errorf("%s/%s: rule kind or name differs: %v", m.Name, a.Name, a.Rule["name"])
			}
		}
		if m.Name == "host" && len(m.DependsOn) != 0 {
			t.Error("host is the root parent and depends on nothing")
		}
		if m.Name != "host" && (len(m.DependsOn) != 1 || m.DependsOn[0].ParentKind != "host") {
			t.Errorf("%s: want one host dependency, got %v", m.Name, m.DependsOn)
		}
	}
	if strings.Join(got, ",") != strings.Join(v1Set, ",") {
		t.Fatalf("v1 set: got %v, want %v", got, v1Set)
	}
	var schema struct {
		Required []string `json:"required"`
	}
	b, err := os.ReadFile(manifestsDir + "/schema.json")
	if err != nil || json.Unmarshal(b, &schema) != nil {
		t.Fatalf("schema.json unreadable: %v", err)
	}
	if strings.Join(schema.Required, ",") != "name,version,discovery,module,metrics,dashboards,alerts,depends_on" {
		t.Fatalf("schema required: %v", schema.Required)
	}
}

func TestManifestHostDownIsTheDependencyParent(t *testing.T) {
	for _, m := range loadAll(t) {
		if m.Name != "host" {
			continue
		}
		for _, a := range m.Alerts {
			if labels, _ := a.Rule["labels"].(map[string]any); labels["down"] == "true" {
				return
			}
		}
	}
	t.Fatal("host has no alert labelled down=true")
}

func TestManifestRefusesUnknownFieldsAndBadPorts(t *testing.T) {
	good := `name: abc
version: "1"
module: {kind: x}
discovery: {process_names: [], ports: [], k8s_labels: {}}
metrics: []
alerts: []
depends_on: []
`
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"unknown field": good + "extra: 1\n",
		"bad port":      strings.Replace(good, "ports: []", "ports: [70000]", 1),
		"bad name":      strings.Replace(good, "name: abc", "name: Abc", 1),
		"self parent":   strings.Replace(good, "depends_on: []", "depends_on: [{parent_kind: abc, equal_labels: [h]}]", 1),
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestListeningPortDiscoveryMatchesManifest(t *testing.T) {
	ms := loadAll(t)
	got := Match(ms, []Socket{
		{Port: 5432, Process: "postgres"},
		{Port: 5999, Process: "Postgres.exe"}, // non-standard port, found by process name
		{Port: 6379},                          // no process visible, found by port
		{Port: 80, Process: "nginx"},          // port 80 is also apache's and nothing else claims it first
		{Port: 31337, Process: "mystery"},
	})
	want := []Detected{
		{"postgres", 5432, "postgres"}, {"postgres", 5999, "Postgres.exe"},
		{"redis", 6379, ""}, {"nginx", 80, "nginx"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
