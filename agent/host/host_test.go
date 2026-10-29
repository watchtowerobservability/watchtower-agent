package host

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestHostMetricsSemconvNames(t *testing.T) {
	var r sink.Recorder
	Collect(&r, nil, time.Now())
	got := r.Names()
	for _, want := range []string{
		"system.cpu.utilization", "system.memory.usage", "system.filesystem.usage",
		"system.network.io", "system.uptime", "system.cpu.load_average.1m",
	} {
		if !got[want] {
			t.Errorf("missing %s; have %v", want, got)
		}
	}
}

func TestProcessTopNCap50(t *testing.T) {
	var samples []ProcSample
	for i := 1; i <= 200; i++ {
		samples = append(samples, ProcSample{PID: int32(i), Name: "p", CPUSecs: float64(i), RSS: uint64(1000 - i)})
	}
	prev := map[int32]float64{}
	var r sink.Recorder
	next := EmitProcesses(&r, samples, prev, 10*time.Second, time.Now())
	if len(next) != 200 {
		t.Fatalf("cumulative map: %d", len(next))
	}
	// second pass has a CPU delta
	for i := range samples {
		samples[i].CPUSecs += float64(samples[i].PID) / 100
	}
	r = sink.Recorder{}
	EmitProcesses(&r, samples, next, 10*time.Second, time.Now())
	cpu, memory := 0, 0
	for _, s := range r.Samples {
		switch s.Name {
		case "process.cpu.utilization":
			cpu++
		case "process.memory.usage":
			memory++
		}
		if s.Attrs["process.pid"] == "" || s.Attrs["process.executable.name"] == "" {
			t.Fatalf("missing process attrs: %v", s.Attrs)
		}
	}
	if cpu != MaxProcesses || memory != MaxProcesses {
		t.Fatalf("want %d each, got cpu=%d memory=%d", MaxProcesses, cpu, memory)
	}
}

func TestDiscoveryCreatesFilesystemChildren(t *testing.T) {
	d := Discovery{{Kind: KindFilesystem, Include: []string{"/", "/data*"}, Exclude: []string{"/data-tmp"}}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	fss := []FS{
		{Device: "a", Mount: "/", Type: "ext4", Used: 1, Free: 2},
		{Device: "b", Mount: "/data1", Type: "xfs", Used: 3, Free: 4},
		{Device: "c", Mount: "/data-tmp", Type: "tmpfs"},
		{Device: "d", Mount: "/boot", Type: "vfat"},
	}
	var r sink.Recorder
	EmitFilesystems(&r, d, fss, time.Now())
	mounts := map[string]bool{}
	for _, s := range r.Samples {
		mounts[s.Attrs["mountpoint"]] = true
		if _, ok := s.Attrs["wt.entity.parent"]; ok {
			t.Fatalf("the parent is derived by the worker, not stamped: %v", s.Attrs)
		}
	}
	if len(mounts) != 2 || !mounts["/"] || !mounts["/data1"] {
		t.Fatalf("children: %v", mounts)
	}
	if got := d.Children(KindFilesystem, []string{"/", "/boot"}); len(got) != 1 {
		t.Fatalf("Children: %v", got)
	}
	if !d.Allow(KindNIC, "eth0") {
		t.Fatal("a kind without a rule is collected whole")
	}
	if (Discovery{{Kind: "bogus"}}).Validate() == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestNodeExporterAliasNames(t *testing.T) {
	var r sink.Recorder
	out := WrapEmit(&r, EmitBoth)
	now := time.Now()
	out.Gauge("system.cpu.load_average.1m", "{thread}", 1.5, nil, now)
	out.Gauge("system.memory.limit", "By", 100, nil, now)
	out.Gauge("system.memory.usage", "By", 40, map[string]string{"state": "used"}, now)
	out.Gauge("system.memory.usage", "By", 60, map[string]string{"state": "free"}, now)
	EmitFilesystems(out, nil, []FS{{Device: "a", Mount: "/", Type: "ext4", Used: 1, Free: 2}}, now)
	EmitIO(out, nil, KindNIC, "system.network.io", map[string][2]uint64{"eth0": {5, 6}}, [2]string{"receive", "transmit"}, now)
	got := r.Names()
	for _, want := range []string{
		"node_load1", "node_memory_MemTotal_bytes", "node_memory_MemAvailable_bytes",
		"node_filesystem_avail_bytes", "node_filesystem_size_bytes",
		"node_network_receive_bytes_total", "node_network_transmit_bytes_total", "system.memory.usage",
	} {
		if !got[want] {
			t.Errorf("missing %s; have %v", want, got)
		}
	}
	for _, s := range r.Samples {
		if s.Name == "node_filesystem_avail_bytes" && (s.Attrs["fstype"] != "ext4" || s.Attrs["mountpoint"] != "/" || s.Value != 2) {
			t.Errorf("avail labels: %v", s)
		}
		if s.Name == "node_filesystem_size_bytes" && s.Value != 3 {
			t.Errorf("size: %v", s)
		}
	}
	// alias-only mode drops the semconv twin of an aliased sample but keeps the rest.
	var only sink.Recorder
	WrapEmit(&only, EmitNodeExporter).Gauge("system.cpu.load_average.1m", "", 1, nil, now)
	WrapEmit(&only, EmitNodeExporter).Gauge("system.uptime", "s", 1, nil, now)
	if n := only.Names(); n["system.cpu.load_average.1m"] || !n["node_load1"] || !n["system.uptime"] {
		t.Errorf("only mode: %v", n)
	}
	if _, err := ParseConfig([]byte(`{"emit":"bogus"}`)); err == nil {
		t.Error("bad emit accepted")
	}
}
