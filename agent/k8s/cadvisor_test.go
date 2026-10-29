package k8s

import (
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const cadvisorText = `# TYPE container_cpu_usage_seconds_total counter
container_cpu_usage_seconds_total{id="/kubepods/x",name="abc",namespace="shop",pod="web-1",container="app",image="shop/web:1"} 12.5
container_cpu_usage_seconds_total{id="/",namespace="",pod="",container=""} 99
container_cpu_usage_seconds_total{namespace="shop",pod="web-1",container="POD"} 1
# TYPE container_network_receive_bytes_total counter
container_network_receive_bytes_total{namespace="shop",pod="web-1",interface="eth0"} 7
`

func TestCadvisorLabelsMappedToK8sAttrs(t *testing.T) {
	fams, err := parseProm(strings.NewReader(cadvisorText))
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	EmitCadvisor(rec, fams, "node1", "prod", time.Now())
	var cpu, netw *sink.Sample
	for _, s := range rec.Snapshot() {
		s := s
		switch s.Name {
		case "container_cpu_usage_seconds_total":
			if cpu != nil {
				t.Fatalf("root cgroup and pause series must be dropped, extra: %+v", s)
			}
			cpu = &s
		case "container_network_receive_bytes_total":
			netw = &s
		}
	}
	if cpu == nil || cpu.Value != 12.5 {
		t.Fatalf("cpu series = %+v", cpu)
	}
	for k, want := range map[string]string{
		"resource.k8s.namespace.name": "shop", "resource.k8s.pod.name": "web-1", "resource.k8s.container.name": "app",
		"resource.container.image.name": "shop/web:1", "resource.k8s.node.name": "node1", "resource.k8s.cluster.name": "prod",
	} {
		if cpu.Attrs[k] != want {
			t.Errorf("%s = %q, want %q", k, cpu.Attrs[k], want)
		}
	}
	if _, ok := cpu.Attrs["id"]; ok {
		t.Error("cgroup id must be dropped")
	}
	if netw == nil || netw.Attrs["interface"] != "eth0" {
		t.Fatalf("network series keeps its interface attribute: %+v", netw)
	}
}
