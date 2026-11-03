package ebpf

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

type fakeResolver struct{ labels map[string]string }

func (fakeResolver) Kernel(a uint64) Frame { return Frame{Addr: a, Name: "do_syscall_64"} }
func (fakeResolver) User(_ uint32, a uint64) Frame {
	return Frame{Addr: a - 0x400000, Module: "/usr/bin/app", BuildID: "abcd"}
}
func (f fakeResolver) Meta(uint32) Meta { return Meta{Service: "app", Labels: f.labels} }

// decoded is just enough of a pprof Profile to assert on.
type decoded struct {
	strs    []string
	samples []map[string]string // label key -> value
	values  [][]uint64
	locs    int
	fnNames []string
	buildID []string
}

func decode(t *testing.T, gz []byte) decoded {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	var d decoded
	var sampleBufs, fnBufs, mapBufs [][]byte
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		raw = raw[n:]
		switch typ {
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(raw)
			raw = raw[n:]
			switch num {
			case 2:
				sampleBufs = append(sampleBufs, v)
			case 3:
				mapBufs = append(mapBufs, v)
			case 4:
				d.locs++
			case 5:
				fnBufs = append(fnBufs, v)
			case 6:
				d.strs = append(d.strs, string(v))
			}
		case protowire.VarintType:
			_, n := protowire.ConsumeVarint(raw)
			raw = raw[n:]
		}
	}
	for _, b := range sampleBufs {
		labels, vals := map[string]string{}, []uint64{}
		for len(b) > 0 {
			num, _, n := protowire.ConsumeTag(b)
			b = b[n:]
			v, n := protowire.ConsumeBytes(b)
			b = b[n:]
			switch num {
			case 2:
				for len(v) > 0 {
					x, n := protowire.ConsumeVarint(v)
					v = v[n:]
					vals = append(vals, x)
				}
			case 3:
				var kv [3]uint64 // Label: key = 1, str = 2
				for len(v) > 0 {
					f, _, n := protowire.ConsumeTag(v)
					x, m := protowire.ConsumeVarint(v[n:])
					v = v[n+m:]
					kv[f] = x
				}
				labels[d.strs[kv[1]]] = d.strs[kv[2]]
			}
		}
		d.samples = append(d.samples, labels)
		d.values = append(d.values, vals)
	}
	for _, b := range fnBufs {
		for len(b) > 0 {
			num, _, n := protowire.ConsumeTag(b)
			b = b[n:]
			x, n := protowire.ConsumeVarint(b)
			b = b[n:]
			if num == 2 {
				d.fnNames = append(d.fnNames, d.strs[x])
			}
		}
	}
	for _, b := range mapBufs {
		for len(b) > 0 {
			num, _, n := protowire.ConsumeTag(b)
			b = b[n:]
			x, n := protowire.ConsumeVarint(b)
			b = b[n:]
			if num == 6 {
				d.buildID = append(d.buildID, d.strs[x])
			}
		}
	}
	return d
}

var labels = map[string]string{
	"host": "h1", "container": "c1", "k8s.pod": "p1",
	"process.executable": "/usr/bin/app", "process.command_line": "app --token=s3cret",
}

func fold(t *testing.T, o FoldOptions) decoded {
	t.Helper()
	es := []Entry{
		{PID: 42, User: []uint64{0x401000, 0x402000}, Kernel: []uint64{0xffffffff81000100}, Value: 5},
		{PID: 42, User: []uint64{0x401000}, Value: 2},
	}
	ps, err := Fold(CPU, es, fakeResolver{labels}, time.Unix(100, 0), time.Minute, o)
	if err != nil || len(ps) != 1 || ps[0].Service != "app" {
		t.Fatalf("fold = %v, %v", ps, err)
	}
	return decode(t, ps[0].Body)
}

func TestFoldStackMapsToPprof(t *testing.T) {
	d := fold(t, FoldOptions{StripArgs: true, Hz: 20})
	if len(d.samples) != 2 {
		t.Fatalf("samples = %d", len(d.samples))
	}
	if d.values[0][0] != 5 || d.values[0][1] != 5*uint64(time.Second/20) {
		t.Fatalf("values = %v", d.values[0])
	}
	for _, k := range []string{"host", "container", "k8s.pod", "process.executable", "pid"} {
		if d.samples[0][k] == "" {
			t.Fatalf("label %s missing: %v", k, d.samples[0])
		}
	}
	if len(d.fnNames) != 1 || d.fnNames[0] != "do_syscall_64" {
		t.Fatalf("kernel frame not resolved locally: %v", d.fnNames)
	}
	if len(d.buildID) != 1 || d.buildID[0] != "abcd" {
		t.Fatalf("user frames must carry module + build id for server symbolization: %v", d.buildID)
	}
	if d.locs != 3 { // two user addresses + one kernel; the repeated 0x401000 is shared
		t.Fatalf("locations = %d", d.locs)
	}
}

func TestStripProcessArgsApplied(t *testing.T) {
	d := fold(t, FoldOptions{StripArgs: true})
	if _, ok := d.samples[0]["process.command_line"]; ok || d.samples[0]["process.executable"] != "app" {
		t.Fatalf("args leaked: %v", d.samples[0])
	}
	for _, s := range d.strs {
		if strings.Contains(s, "s3cret") {
			t.Fatal("secret in string table")
		}
	}
	d = fold(t, FoldOptions{PlainPID: true})
	if d.samples[0]["process.command_line"] == "" || d.samples[0]["pid"] != "42" {
		t.Fatalf("opt-out ignored: %v", d.samples[0])
	}
	if h := fold(t, FoldOptions{StripArgs: true}).samples[0]["pid"]; h == "42" || h == "" {
		t.Fatalf("pid not hashed: %q", h)
	}
}

func TestOverheadGuardHalvesRate(t *testing.T) {
	if _, err := ParseConfig([]byte(`{"runtime_stacks":["dotnet"]}`)); err != nil {
		t.Fatalf("dotnet is a runtime_stacks value: %v", err)
	}
	if _, err := ParseConfig([]byte(`{"python_stacks":false,"runtime_stacks":["python_legacy"]}`)); err == nil {
		t.Fatal("python_legacy without python_stacks must be refused")
	}
	g := Guard{Budget: 0.01, Rate: 19}
	if g.Observe(0.1, 60) {
		t.Fatal("under budget must not halve")
	}
	if !g.Observe(1.2, 60) || g.Rate != 9 {
		t.Fatalf("rate = %d", g.Rate)
	}
	for i := 0; i < 10; i++ {
		g.Observe(60, 60)
	}
	if g.Rate != 1 {
		t.Fatalf("rate must floor at 1, got %d", g.Rate)
	}
}

func TestKallsymsResolver(t *testing.T) {
	f, err := os.Open("testdata/kallsyms")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	k := ParseKallsyms(f)
	for addr, want := range map[uint64]string{
		0xffffffff81000100: "do_syscall_64",
		0xffffffff81000150: "do_syscall_64",
		0xffffffff81000200: "finish_task_switch",
		0xffffffff81000000: "_stext",
	} {
		if got := k.Lookup(addr); got != want {
			t.Errorf("Lookup(%#x) = %q, want %q", addr, got, want)
		}
	}
	if got := k.Lookup(0x1000); got != "" {
		t.Errorf("below the table = %q", got)
	}
}

func TestPerfMapAndMaps(t *testing.T) {
	p := ParsePerfMap(strings.NewReader("7f0000001000 40 LJavaFoo.bar;\nbad line\n"))
	if n, ok := p.Lookup(0x7f0000001010); !ok || n != "LJavaFoo.bar;" {
		t.Fatalf("perf map = %q %v", n, ok)
	}
	if _, ok := p.Lookup(0x7f0000001040); ok {
		t.Fatal("end is exclusive")
	}
	ms := ParseMaps(strings.NewReader("00400000-00452000 r-xp 00002000 08:02 173521 /usr/bin/app\n00652000-00653000 rw-p 00052000 08:02 173521 /usr/bin/app\n"))
	m, ok := FindMapping(ms, 0x401000)
	if !ok || m.Path != "/usr/bin/app" || m.Offset != 0x2000 || len(ms) != 1 {
		t.Fatalf("maps = %+v %v", ms, ok)
	}
}

func TestModuleDisabledByDefault(t *testing.T) {
	c, err := ParseConfig(nil)
	if err != nil || c.Enabled || c.SampleHz != 19 || c.UploadIntervalS != 60 || !c.OffCPU || !c.Strip() || !c.DwarfUnwind || c.OffCPUDwarf || len(c.RuntimeStacks) != 0 {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
	if _, err := ParseConfig([]byte(`{"enabled":true,"exec":"/bin/sh"}`)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, nil, "https://x", "wti_t"); err != nil {
		t.Fatalf("disabled module must not touch the kernel: %v", err)
	}
}
