package gpu

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestNvidiaSmiCSVParse(t *testing.T) {
	f, err := os.Open("testdata/nvidia-smi.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := ParseNvidiaCSV(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].Name != "NVIDIA A100-SXM4-40GB" || rs[0].UtilPercent != 37 || rs[0].MemUsedBytes != 1024*1024*1024 {
		t.Fatalf("readings: %+v", rs)
	}
	if !math.IsNaN(rs[1].PowerW) {
		t.Fatalf("[N/A] must be missing, got %v", rs[1].PowerW)
	}
	var r sink.Recorder
	Emit(&r, host.Discovery{{Kind: host.KindGPU, Exclude: []string{"1"}}}, rs, time.Now())
	n := r.Names()
	for _, want := range []string{"hw.gpu.utilization", "hw.gpu.memory.usage", "hw.gpu.temperature", "hw.gpu.power"} {
		if !n[want] {
			t.Fatalf("missing %s", want)
		}
	}
	for _, s := range r.Samples {
		if s.Attrs["gpu.index"] != "0" {
			t.Fatalf("excluded gpu leaked: %v", s.Attrs)
		}
		if s.Name == "hw.gpu.utilization" && s.Value != 0.37 {
			t.Fatalf("utilization is a fraction: %v", s.Value)
		}
	}
	if _, err := ParseNvidiaCSV(strings.NewReader("garbage")); err == nil {
		t.Fatal("bad csv accepted")
	}
}

func TestNvidiaECCParseAndEmit(t *testing.T) {
	rs, err := ParseNvidiaCSV(strings.NewReader("0, A100, GPU-aaa, 10, 100, 1000, 40, 50\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseNvidiaECC(strings.NewReader("0, 3, [N/A]\n"), rs); err != nil {
		t.Fatal(err)
	}
	if rs[0].ECCCorrected != 3 || !math.IsNaN(rs[0].ECCUncorrected) {
		t.Fatalf("%+v", rs[0])
	}
	var r sink.Recorder
	Emit(&r, host.Discovery{}, rs, time.Unix(0, 0))
	n := 0
	for _, s := range r.Snapshot() {
		if s.Name == "hw.gpu.ecc.errors" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want one ecc sample, got %d", n)
	}
}

func TestXIDErrorsParsed(t *testing.T) {
	log := "Oct 29 kernel: NVRM: Xid (PCI:0000:3b:00): 79, pid=1234, name=python, GPU has fallen off the bus.\n" +
		"Oct 29 kernel: unrelated line\n" +
		"Oct 29 kernel: NVRM: Xid (PCI:0000:3b:00): 48, An uncorrectable double bit error occurred\n"
	xs := ParseXID(strings.NewReader(log))
	if len(xs) != 2 || xs[0].Code != 79 || xs[0].PCI != "0000:3b:00" || xs[1].Code != 48 || !strings.Contains(xs[0].Detail, "fallen off") {
		t.Fatalf("xids: %+v", xs)
	}
	var r sink.Recorder
	EmitXID(&r, xs, time.Unix(0, 0))
	if !r.Names()["hw.gpu.xid.errors"] {
		t.Fatalf("names: %v", r.Names())
	}
	// the tail starts at the end, then returns only complete new lines
	p := t.TempDir() + "/kern.log"
	if err := os.WriteFile(p, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := &XIDTail{Path: p}
	if got, _ := tail.Poll(); len(got) != 0 {
		t.Fatalf("history replayed: %+v", got)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("NVRM: Xid (PCI:0000:86:00): 31, pid=9\nNVRM: Xid (PCI:0000:86:00): 6")
	_ = f.Close()
	got, _ := tail.Poll()
	if len(got) != 1 || got[0].Code != 31 {
		t.Fatalf("tail: %+v", got)
	}
}

func TestNvidiaExtrasParse(t *testing.T) {
	procs := ParseNvidiaProcs(strings.NewReader("GPU-aaa, 4242, python, 2048\nGPU-aaa, 7, other, [N/A]\n"))
	if len(procs) != 2 || procs[0].MemBytes != 2048*1024*1024 || procs[1].MemBytes != 0 {
		t.Fatalf("procs: %+v", procs)
	}
	migs := ParseNvidiaL(strings.NewReader("GPU 0: NVIDIA A100 (UUID: GPU-aaa)\n  MIG 1g.5gb     Device  0: (UUID: MIG-111)\n  MIG 2g.10gb    Device  1: (UUID: MIG-222)\n"))
	if len(migs) != 2 || migs[0].GPUIndex != "0" || migs[1].Profile != "2g.10gb" {
		t.Fatalf("migs: %+v", migs)
	}
	links := ParseNvlink(strings.NewReader("GPU 0: NVIDIA A100 (UUID: GPU-aaa)\n\t Link 0: 25 GB/s\n\t Link 1: <inactive>\n"))
	if len(links) != 1 || links[0].Speed != 25e9 {
		t.Fatalf("links: %+v", links)
	}
	var r sink.Recorder
	rs := []Reading{{Index: "0", ID: "GPU-aaa", Vendor: "nvidia"}}
	EmitExtras(&r, host.Discovery{}, rs, Extras{Procs: procs, MIGs: migs, Links: links}, time.Unix(0, 0))
	for _, want := range []string{"hw.gpu.process.memory.usage", "hw.gpu.mig.instance", "hw.gpu.nvlink.speed", "hw.gpu.nvlink.links.active"} {
		if !r.Names()[want] {
			t.Errorf("missing %s", want)
		}
	}
}

func TestRocmJSONParse(t *testing.T) {
	rs, err := ParseRocmJSON([]byte(`{"card0":{"GPU use (%)":"12","VRAM Total Used Memory (B)":"2048",
		"Temperature (Sensor edge) (C)":"41.0","Average Graphics Package Power (W)":"33.5","Card series":"Instinct MI210"},"system":{"x":"y"}}`))
	if err != nil || len(rs) != 1 {
		t.Fatalf("%v %v", rs, err)
	}
	r := rs[0]
	if r.UtilPercent != 12 || r.MemUsedBytes != 2048 || r.TempC != 41 || r.PowerW != 33.5 || r.Name != "Instinct MI210" {
		t.Fatalf("%+v", r)
	}
}
