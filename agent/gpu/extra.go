package gpu

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/host"
	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// MaxProcsPerGPU caps the per-process memory series per GPU (largest first).
const MaxProcsPerGPU = 20

// NvidiaProcQuery lists compute processes with their GPU memory.
var NvidiaProcQuery = []string{
	"--query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory",
	"--format=csv,noheader,nounits",
}

// Proc is one process using a GPU. MemBytes is NaN-free: unreported memory is 0.
type Proc struct {
	GPUID    string
	PID      string
	Name     string
	MemBytes float64
}

// ParseNvidiaProcs parses NvidiaProcQuery output (memory in MiB). A "No running processes" line
// or empty output is no processes.
func ParseNvidiaProcs(r io.Reader) []Proc {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1
	rows, _ := cr.ReadAll()
	var out []Proc
	for _, f := range rows {
		if len(f) != 4 {
			continue
		}
		mem := num(f[3])
		if math.IsNaN(mem) {
			mem = 0
		}
		out = append(out, Proc{GPUID: strings.TrimSpace(f[0]), PID: strings.TrimSpace(f[1]), Name: strings.TrimSpace(f[2]), MemBytes: mem * 1024 * 1024})
	}
	return out
}

// MIG is one multi-instance-GPU slice from `nvidia-smi -L`.
type MIG struct {
	GPUIndex string
	Profile  string // e.g. 1g.5gb
	ID       string // the MIG-... uuid
}

var (
	gpuLine = regexp.MustCompile(`^GPU (\d+):`)
	migLine = regexp.MustCompile(`^\s*MIG (\S+)\s+Device\s+\d+:.*\(UUID: (MIG-[^)\s]+)\)`)
)

// ParseNvidiaL extracts MIG instances (attributed to the GPU line above them) from `nvidia-smi -L`.
func ParseNvidiaL(r io.Reader) []MIG {
	var out []MIG
	cur := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if m := gpuLine.FindStringSubmatch(line); m != nil {
			cur = m[1]
		} else if m := migLine.FindStringSubmatch(line); m != nil {
			out = append(out, MIG{GPUIndex: cur, Profile: m[1], ID: m[2]})
		}
	}
	return out
}

// Link is one active NVLink link with its speed in bytes per second.
type Link struct {
	GPUIndex string
	Link     string
	Speed    float64
}

var linkLine = regexp.MustCompile(`^\s*Link (\d+):\s*([\d.]+)\s*(GB|MB)/s`)

// ParseNvlink parses `nvidia-smi nvlink -s`. Inactive links ("<inactive>") are left out.
func ParseNvlink(r io.Reader) []Link {
	var out []Link
	cur := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if m := gpuLine.FindStringSubmatch(line); m != nil {
			cur = m[1]
		} else if m := linkLine.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseFloat(m[2], 64)
			if err != nil {
				continue
			}
			unit := 1e9
			if m[3] == "MB" {
				unit = 1e6
			}
			out = append(out, Link{GPUIndex: cur, Link: m[1], Speed: v * unit})
		}
	}
	return out
}

// Extras are the optional per-poll NVIDIA readings beyond the base query.
type Extras struct {
	Procs []Proc
	MIGs  []MIG
	Links []Link
}

// NvidiaExtras runs the extra queries; each is optional and a failure leaves its list empty.
func NvidiaExtras(ctx context.Context, path string) Extras {
	var e Extras
	if b, err := run(ctx, path, NvidiaProcQuery...); err == nil {
		e.Procs = ParseNvidiaProcs(bytes.NewReader(b))
	}
	if b, err := run(ctx, path, "-L"); err == nil {
		e.MIGs = ParseNvidiaL(bytes.NewReader(b))
	}
	if b, err := run(ctx, path, "nvlink", "-s"); err == nil {
		e.Links = ParseNvlink(bytes.NewReader(b))
	}
	return e
}

// EmitExtras writes hw.gpu.process.memory.usage (top MaxProcsPerGPU per GPU), hw.gpu.mig.instance
// (value 1 per slice) and hw.gpu.nvlink.speed plus hw.gpu.nvlink.links.active per GPU. The
// readings give the GPU index/uuid mapping needed to apply the discovery rules.
func EmitExtras(out sink.Sink, d host.Discovery, rs []Reading, e Extras, at time.Time) {
	idOf := map[string]string{} // uuid -> index
	for _, r := range rs {
		idOf[r.ID] = r.Index
	}
	byGPU := map[string][]Proc{}
	for _, p := range e.Procs {
		byGPU[p.GPUID] = append(byGPU[p.GPUID], p)
	}
	for id, ps := range byGPU {
		idx := idOf[id]
		if idx == "" || !d.Allow(host.KindGPU, idx) {
			continue
		}
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].MemBytes != ps[j].MemBytes {
				return ps[i].MemBytes > ps[j].MemBytes
			}
			return ps[i].PID < ps[j].PID
		})
		for _, p := range ps[:min(len(ps), MaxProcsPerGPU)] {
			out.Gauge("hw.gpu.process.memory.usage", "By", p.MemBytes, map[string]string{
				"hw.id": id, "gpu.index": idx, "process.pid": p.PID, "process.executable.name": p.Name}, at)
		}
	}
	for _, m := range e.MIGs {
		if d.Allow(host.KindGPU, m.GPUIndex) {
			out.Gauge("hw.gpu.mig.instance", "1", 1, map[string]string{
				"gpu.index": m.GPUIndex, "gpu.mig.profile": m.Profile, "hw.id": m.ID}, at)
		}
	}
	active := map[string]float64{}
	for _, l := range e.Links {
		if !d.Allow(host.KindGPU, l.GPUIndex) {
			continue
		}
		active[l.GPUIndex]++
		out.Gauge("hw.gpu.nvlink.speed", "By/s", l.Speed, map[string]string{"gpu.index": l.GPUIndex, "gpu.nvlink.link": l.Link}, at)
	}
	for idx, n := range active {
		out.Gauge("hw.gpu.nvlink.links.active", "{link}", n, map[string]string{"gpu.index": idx}, at)
	}
}

// XID is one NVIDIA driver Xid event from the kernel log.
type XID struct {
	PCI    string
	Code   int
	Detail string
}

// NVRM: Xid (PCI:0000:3b:00): 79, pid=1234, name=python, GPU has fallen off the bus.
var xidLine = regexp.MustCompile(`NVRM: Xid \(PCI:([0-9a-fA-F:.]+)\): (\d+)(?:,\s*(.*))?$`)

// ParseXID returns the Xid events in kernel log text, in order.
func ParseXID(r io.Reader) []XID {
	var out []XID
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		m := xidLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		code, _ := strconv.Atoi(m[2])
		out = append(out, XID{PCI: m[1], Code: code, Detail: strings.TrimSpace(m[3])})
	}
	return out
}

// XIDTail reads new Xid events from a kernel log file (for example /var/log/kern.log) on each
// Poll. The first poll starts at the end, so history is not replayed; a shrunken file (rotation)
// is re-read from its start. The agent only needs read access to that one file.
type XIDTail struct {
	Path string
	off  int64
	init bool
}

// maxXIDRead bounds the bytes read in one poll.
const maxXIDRead = 4 << 20

// Poll returns the events appended since the last poll.
func (x *XIDTail) Poll() ([]XID, error) {
	f, err := os.Open(x.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !x.init {
		x.init, x.off = true, st.Size()
		return nil, nil
	}
	if st.Size() < x.off {
		x.off = 0
	}
	if _, err := f.Seek(x.off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxXIDRead))
	if err != nil {
		return nil, err
	}
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[:i+1] // leave a half-written line for the next poll
	} else {
		b = nil
	}
	x.off += int64(len(b))
	return ParseXID(bytes.NewReader(b)), nil
}

// EmitXID counts each event on hw.gpu.xid.errors (a delta of 1, by code and PCI address) and
// logs it at ERROR so the cause text is searchable.
func EmitXID(out sink.Sink, xs []XID, at time.Time) {
	for _, x := range xs {
		a := map[string]string{"gpu.xid.code": strconv.Itoa(x.Code), "gpu.pci": x.PCI}
		out.Gauge("hw.gpu.xid.errors", "{error}", 1, a, at)
		out.Log("ERROR", "NVIDIA Xid "+strconv.Itoa(x.Code)+" on "+x.PCI+": "+x.Detail, a, at)
	}
}
