package gpu

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func msg(fields ...func([]byte) []byte) []byte {
	var b []byte
	for _, f := range fields {
		b = f(b)
	}
	return b
}

func pbStr(n protowire.Number, s string) func([]byte) []byte {
	return func(b []byte) []byte {
		return protowire.AppendString(protowire.AppendTag(b, n, protowire.BytesType), s)
	}
}

func sub(n protowire.Number, m []byte) func([]byte) []byte {
	return func(b []byte) []byte { return protowire.AppendBytes(protowire.AppendTag(b, n, protowire.BytesType), m) }
}

func varint(n protowire.Number, v uint64) func([]byte) []byte {
	return func(b []byte) []byte {
		return protowire.AppendVarint(protowire.AppendTag(b, n, protowire.VarintType), v)
	}
}

// A ListPodResourcesResponse with one pod: its trainer container holds GPU-aaa, its sidecar a
// non-GPU device and CPU ids (a varint field that must be skipped).
func podResourcesFixture() []byte {
	gpuDev := msg(pbStr(1, "nvidia.com/gpu"), pbStr(2, "GPU-aaa"))
	otherDev := msg(pbStr(1, "example.com/fpga"), pbStr(2, "GPU-bbb"))
	trainer := msg(pbStr(1, "trainer"), sub(2, gpuDev), varint(5, 7))
	sidecar := msg(pbStr(1, "sidecar"), sub(2, otherDev))
	pod := msg(pbStr(1, "train-0"), pbStr(2, "ml"), sub(3, trainer), sub(3, sidecar))
	return msg(sub(1, pod))
}

func TestParsePodResourcesKeepsGPUDevices(t *testing.T) {
	got, err := ParsePodResources(podResourcesFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["GPU-aaa"] != (PodGPU{Pod: "train-0", Namespace: "ml", Container: "trainer"}) {
		t.Fatalf("assignment: %+v", got)
	}
	if _, err := ParsePodResources([]byte{0x0a, 0x05, 0x01}); err == nil {
		t.Fatal("a truncated message must fail")
	}
}

func TestAttributedGPUsCarryThePodAndAllocation(t *testing.T) {
	rs, err := ParseNvidiaCSV(strings.NewReader("0, A100, GPU-aaa, 90, 100, 1000, 40, 50\n1, A100, GPU-ccc, 0, 0, 1000, 30, 20\n"))
	if err != nil {
		t.Fatal(err)
	}
	pods, err := ParsePodResources(podResourcesFixture())
	if err != nil {
		t.Fatal(err)
	}
	Attribute(rs, pods)
	var r sink.Recorder
	Emit(&r, host.Discovery{}, rs, time.Now())
	alloc := map[string]float64{}
	for _, s := range r.Samples {
		if s.Name == "hw.gpu.allocated" {
			alloc[s.Attrs["hw.id"]] = s.Value
		}
		if s.Name == "hw.gpu.utilization" && s.Attrs["hw.id"] == "GPU-aaa" &&
			(s.Attrs["k8s.pod.name"] != "train-0" || s.Attrs["k8s.namespace.name"] != "ml" || s.Attrs["k8s.container.name"] != "trainer") {
			t.Fatalf("pod attrs: %v", s.Attrs)
		}
		if s.Attrs["hw.id"] == "GPU-ccc" && s.Attrs["k8s.pod.name"] != "" {
			t.Fatalf("an unassigned GPU names no pod: %v", s.Attrs)
		}
	}
	if alloc["GPU-aaa"] != 1 || alloc["GPU-ccc"] != 0 || len(alloc) != 2 {
		t.Fatalf("allocation: %v", alloc)
	}
	// Without the lookup there is no allocation metric (unknown, not unallocated).
	rs[0].Tracked, rs[1].Tracked = false, false
	var plain sink.Recorder
	Emit(&plain, host.Discovery{}, rs, time.Now())
	if plain.Names()["hw.gpu.allocated"] {
		t.Fatal("hw.gpu.allocated without a pod-resources lookup")
	}
}
