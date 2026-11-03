package host

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// Linux kernel inputs (CON-016, the Telegraf kernel, kernel_vmstat, interrupts, hugepages, slab,
// nstat and sensors inputs), read from /proc and /sys under root. A missing file is skipped.

// vmstatKeys are the /proc/vmstat counters kept; the full file has ~150, most of them noise.
var vmstatKeys = map[string]bool{
	"pgpgin": true, "pgpgout": true, "pswpin": true, "pswpout": true, "pgfault": true, "pgmajfault": true,
	"pgsteal_kswapd": true, "pgsteal_direct": true, "pgscan_kswapd": true, "pgscan_direct": true,
	"oom_kill": true, "thp_fault_alloc": true, "compact_stall": true, "allocstall_normal": true,
}

// snmpKeys are the /proc/net/snmp counters kept, as `<Proto><Field>` (nstat names).
var snmpKeys = map[string]bool{
	"TcpActiveOpens": true, "TcpPassiveOpens": true, "TcpAttemptFails": true, "TcpEstabResets": true,
	"TcpInSegs": true, "TcpOutSegs": true, "TcpRetransSegs": true, "TcpInErrs": true, "TcpOutRsts": true,
	"UdpInDatagrams": true, "UdpOutDatagrams": true, "UdpNoPorts": true, "UdpInErrors": true,
	"UdpRcvbufErrors": true, "UdpSndbufErrors": true, "IpInDiscards": true, "IpOutDiscards": true,
	"IcmpInErrors": true,
}

// CollectKernel emits the kernel inputs on Linux; elsewhere it does nothing.
func CollectKernel(out sink.Sink, root string, at time.Time) {
	if runtime.GOOS != "linux" {
		return
	}
	p := func(rel string) string { return filepath.Join(root, rel) }
	if f, err := os.Open(p("proc/stat")); err == nil {
		EmitProcStat(out, f, at)
		f.Close()
	}
	if f, err := os.Open(p("proc/vmstat")); err == nil {
		for k, v := range keyValues(f, vmstatKeys) {
			out.Sum("system.vmstat."+k, "{event}", v, nil, at)
		}
		f.Close()
	}
	if f, err := os.Open(p("proc/meminfo")); err == nil {
		EmitMeminfoDepth(out, f, at)
		f.Close()
	}
	if f, err := os.Open(p("proc/net/snmp")); err == nil {
		for k, v := range ParseSNMP(f) {
			out.Sum("system.network.nstat", "{event}", v, map[string]string{"counter": k}, at)
		}
		f.Close()
	}
	if b, err := os.ReadFile(p("proc/sys/kernel/random/entropy_avail")); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
			out.Gauge("system.entropy.available", "{bit}", v, nil, at)
		}
	}
	EmitHwmon(out, p("sys/class/hwmon"), at)
}

// EmitProcStat writes the interrupt total (`intr`), soft interrupts and boot time from /proc/stat.
func EmitProcStat(out sink.Sink, r io.Reader, at time.Time) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20) // `intr` lists every IRQ on one line
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(f[1], 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "intr":
			out.Sum("system.interrupts", "{interrupt}", v, map[string]string{"type": "hard"}, at)
		case "softirq":
			out.Sum("system.interrupts", "{interrupt}", v, map[string]string{"type": "soft"}, at)
		case "btime":
			out.Gauge("system.boot_time", "s", v, nil, at)
		}
	}
}

// keyValues reads `key value` lines, keeping the keys in keep.
func keyValues(r io.Reader, keep map[string]bool) map[string]float64 {
	m := map[string]float64{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && keep[f[0]] {
			if v, err := strconv.ParseFloat(f[1], 64); err == nil {
				m[f[0]] = v
			}
		}
	}
	return m
}

// EmitMeminfoDepth writes huge pages and slab memory from /proc/meminfo.
func EmitMeminfoDepth(out sink.Sink, r io.Reader, at time.Time) {
	m := map[string]float64{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		f := strings.Fields(rest)
		if !ok || len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		if len(f) == 2 && f[1] == "kB" {
			v *= 1024
		}
		m[k] = v
	}
	for k, state := range map[string]string{"HugePages_Total": "total", "HugePages_Free": "free", "HugePages_Rsvd": "reserved", "HugePages_Surp": "surplus"} {
		if v, ok := m[k]; ok {
			out.Gauge("system.memory.hugepages", "{page}", v, map[string]string{"state": state}, at)
		}
	}
	if v, ok := m["Hugepagesize"]; ok {
		out.Gauge("system.memory.hugepages.page_size", "By", v, nil, at)
	}
	for k, state := range map[string]string{"SReclaimable": "reclaimable", "SUnreclaim": "unreclaimable"} {
		if v, ok := m[k]; ok {
			out.Gauge("system.memory.slab.usage", "By", v, map[string]string{"state": state}, at)
		}
	}
}

// ParseSNMP reads /proc/net/snmp (a header line and a value line per protocol) into nstat names.
func ParseSNMP(r io.Reader) map[string]float64 {
	m := map[string]float64{}
	sc := bufio.NewScanner(r)
	var head []string
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		proto := strings.TrimSuffix(f[0], ":")
		if head == nil || head[0] != f[0] {
			head = f
			continue
		}
		for i := 1; i < len(f) && i < len(head); i++ {
			k := proto + head[i]
			if v, err := strconv.ParseFloat(f[i], 64); err == nil && snmpKeys[k] {
				m[k] = v
			}
		}
		head = nil
	}
	return m
}

// EmitHwmon writes hw.temperature (degrees Celsius) for every hwmon temp*_input sensor.
func EmitHwmon(out sink.Sink, dir string, at time.Time) {
	chips, _ := filepath.Glob(filepath.Join(dir, "hwmon*"))
	for _, c := range chips {
		name := readTrim(filepath.Join(c, "name"))
		inputs, _ := filepath.Glob(filepath.Join(c, "temp*_input"))
		for _, in := range inputs {
			v, err := strconv.ParseFloat(readTrim(in), 64)
			if err != nil {
				continue
			}
			label := readTrim(strings.TrimSuffix(in, "_input") + "_label")
			if label == "" {
				label = strings.TrimSuffix(filepath.Base(in), "_input")
			}
			out.Gauge("hw.temperature", "Cel", v/1000, map[string]string{"hw.chip": name, "hw.sensor": label}, at)
		}
	}
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
