package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func find(r *sink.Recorder, name, k, v string) (float64, bool) {
	for _, s := range r.Snapshot() {
		if s.Name == name && (k == "" || s.Attrs[k] == v) {
			return s.Value, true
		}
	}
	return 0, false
}

func TestKernelInputsParseProcFiles(t *testing.T) {
	var r sink.Recorder
	at := time.Unix(0, 0)
	EmitProcStat(&r, strings.NewReader("cpu  1 2 3\nintr 12345 0 7 0\nctxt 99\nbtime 1700000000\nsoftirq 777 1 2\n"), at)
	EmitMeminfoDepth(&r, strings.NewReader("MemTotal: 100 kB\nHugePages_Total:       4\nHugePages_Free:        3\nHugepagesize:       2048 kB\nSReclaimable:      10 kB\nSUnreclaim:        5 kB\n"), at)
	snmp := ParseSNMP(strings.NewReader("Ip: Forwarding InDiscards\nIp: 1 3\nTcp: RtoAlgorithm RetransSegs CurrEstab\nTcp: 1 42 9\nUdp: InDatagrams NoPorts\nUdp: 100 2\n"))
	for _, c := range []struct {
		name, k, v string
		want       float64
	}{
		{"system.interrupts", "type", "hard", 12345},
		{"system.interrupts", "type", "soft", 777},
		{"system.boot_time", "", "", 1700000000},
		{"system.memory.hugepages", "state", "total", 4},
		{"system.memory.hugepages.page_size", "", "", 2048 * 1024},
		{"system.memory.slab.usage", "state", "unreclaimable", 5 * 1024},
	} {
		if got, ok := find(&r, c.name, c.k, c.v); !ok || got != c.want {
			t.Errorf("%s{%s=%s} = %v, %v; want %v", c.name, c.k, c.v, got, ok, c.want)
		}
	}
	if snmp["TcpRetransSegs"] != 42 || snmp["UdpNoPorts"] != 2 || snmp["IpInDiscards"] != 3 {
		t.Errorf("snmp %v", snmp)
	}
	if _, kept := snmp["TcpCurrEstab"]; kept {
		t.Error("kept a counter outside the list")
	}
}

func TestHwmonTemperatures(t *testing.T) {
	dir := t.TempDir()
	chip := filepath.Join(dir, "hwmon0")
	if err := os.MkdirAll(chip, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"name": "coretemp\n", "temp1_input": "45000\n", "temp1_label": "Package id 0\n", "temp2_input": "51500\n"} {
		if err := os.WriteFile(filepath.Join(chip, f), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var r sink.Recorder
	EmitHwmon(&r, dir, time.Unix(0, 0))
	if v, ok := find(&r, "hw.temperature", "hw.sensor", "Package id 0"); !ok || v != 45 {
		t.Errorf("labelled sensor %v %v", v, ok)
	}
	if v, ok := find(&r, "hw.temperature", "hw.sensor", "temp2"); !ok || v != 51.5 {
		t.Errorf("unlabelled sensor %v %v", v, ok)
	}
}

func TestSelectedProcessesAlwaysReported(t *testing.T) {
	var r sink.Recorder
	EmitSelected(&r, []ProcSample{{PID: 1, Name: "postgres", CPUSecs: 3, RSS: 10}, {PID: 2, Name: "bash"}}, []string{"post*"}, time.Unix(0, 0))
	if v, ok := find(&r, "process.cpu.time", "process.executable.name", "postgres"); !ok || v != 3 {
		t.Errorf("cpu %v %v", v, ok)
	}
	if _, ok := find(&r, "process.cpu.time", "process.executable.name", "bash"); ok {
		t.Error("reported an unselected process")
	}
}
