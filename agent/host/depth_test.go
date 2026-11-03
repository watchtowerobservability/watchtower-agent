package host

import (
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestParseProcNetTCPCountsStates(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D2A4 01 00000000:00000000 00:00000000 00000000  1000        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F90 0100007F:D2A6 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:1F90 0100007F:D2A8 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000
`
	counts := map[string]int{}
	ParseProcNetTCP(strings.NewReader(table), counts)
	if counts["listen"] != 1 || counts["established"] != 2 || counts["time_wait"] != 1 || len(counts) != 3 {
		t.Fatalf("counts = %v", counts)
	}
}

func TestNodeExporterDepthAliases(t *testing.T) {
	var r sink.Recorder
	out := WrapEmit(&r, EmitNodeExporter)
	now := time.Now()
	EmitCPUTimes(out, []cpu.TimesStat{{CPU: "cpu3", User: 12.5, Iowait: 1}}, now)
	EmitDiskDepth(out, nil, map[string]disk.IOCountersStat{"sda": {ReadCount: 7, WriteCount: 9, ReadTime: 1500, IoTime: 2000, IopsInProgress: 2}}, now)
	EmitNICDepth(out, nil, []gnet.IOCountersStat{{Name: "eth0", PacketsRecv: 5, Errout: 1, Dropin: 3}}, now)
	EmitFilesystems(out, nil, []FS{{Device: "a", Mount: "/", Type: "ext4", Used: 1, Free: 2, InodesUsed: 10, InodesFree: 90}}, now)
	out.Gauge("system.network.connections", "{connection}", 4, map[string]string{"protocol": "tcp", "state": "established"}, now)
	out.Gauge("system.processes.count", "{process}", 3, map[string]string{"status": "running"}, now)
	out.Gauge("system.paging.usage", "By", 64, map[string]string{"state": "free"}, now)
	want := map[string]float64{
		"node_disk_reads_completed_total": 7, "node_disk_writes_completed_total": 9, "node_disk_read_time_seconds_total": 1.5,
		"node_disk_io_time_seconds_total": 2, "node_disk_io_now": 2, "node_network_receive_packets_total": 5,
		"node_network_transmit_errs_total": 1, "node_network_receive_drop_total": 3, "node_filesystem_files": 100,
		"node_filesystem_files_free": 90, "node_tcp_connection_states": 4, "node_procs_running": 3, "node_memory_SwapFree_bytes": 64,
	}
	seen := map[string]bool{}
	for _, s := range r.Samples {
		if v, ok := want[s.Name]; ok && s.Value == v {
			seen[s.Name] = true
		}
		if s.Name == "node_cpu_seconds_total" && s.Attrs["mode"] == "user" && (s.Attrs["cpu"] != "3" || s.Value != 12.5) {
			t.Errorf("cpu seconds = %v", s)
		}
		if s.Name == "node_tcp_connection_states" && (s.Attrs["state"] != "established" || s.Attrs["protocol"] != "") {
			t.Errorf("tcp states labels = %v", s.Attrs)
		}
	}
	for n := range want {
		if !seen[n] {
			t.Errorf("missing %s", n)
		}
	}
	if !r.Names()["node_cpu_seconds_total"] {
		t.Error("missing node_cpu_seconds_total")
	}
}
