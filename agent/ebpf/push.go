package ebpf

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"time"
	"github.com/watchtowerobservability/watchtower-agent/internal/netguard"

	"google.golang.org/protobuf/encoding/protowire"
)

// Kind is the sample type of a profile.
type Kind string

// Sample types uploaded to /v1/profiles.
const (
	CPU    Kind = "cpu"
	OffCPU Kind = "offcpu"
	// Lock is nanoseconds blocked in lock calls (package ebpf_profiler).
	Lock Kind = "lock_contention"
)

// Entry is one row of the kernel count map. Value is a sample count for CPU and nanoseconds
// blocked for OffCPU. Stacks are leaf first.
type Entry struct {
	PID          uint32
	User, Kernel []uint64
	Value        uint64
}

// Frame is one resolved stack frame. Addr is module-relative when Module is set.
type Frame struct {
	Addr    uint64
	Module  string
	BuildID string
	Name    string // set only when resolved on the host (kernel, perf map)
}

// Meta says which service a pid belongs to and the labels its samples carry.
type Meta struct {
	Service string
	Labels  map[string]string // host, container, k8s.pod, process.executable, process.command_line, pid
}

// Resolver turns addresses and pids into frames and metadata.
type Resolver interface {
	User(pid uint32, addr uint64) Frame
	Kernel(addr uint64) Frame
	Meta(pid uint32) Meta
}

// Profile is one pprof upload.
type Profile struct {
	Service string
	Kind    Kind
	Body    []byte // gzip pprof
}

// FoldOptions are the privacy knobs applied while folding.
type FoldOptions struct {
	StripArgs bool
	PlainPID  bool
	Hz        int // CPU sampling rate, to convert samples to nanoseconds
}

// Fold builds one gzip pprof per service from the drained map entries.
func Fold(kind Kind, entries []Entry, r Resolver, start time.Time, dur time.Duration, o FoldOptions) ([]Profile, error) {
	by := map[string]*builder{}
	metas := map[uint32]Meta{}
	for _, e := range entries {
		if e.Value == 0 {
			continue
		}
		m, ok := metas[e.PID]
		if !ok {
			m = r.Meta(e.PID)
			metas[e.PID] = m
		}
		b := by[m.Service]
		if b == nil {
			b = newBuilder(kind, start, dur, o.Hz)
			by[m.Service] = b
		}
		b.add(e, r, sanitize(m.Labels, e.PID, o))
	}
	services := make([]string, 0, len(by))
	for s := range by {
		services = append(services, s)
	}
	sort.Strings(services)
	out := make([]Profile, 0, len(services))
	for _, s := range services {
		body, err := by[s].gzip()
		if err != nil {
			return nil, err
		}
		out = append(out, Profile{Service: s, Kind: kind, Body: body})
	}
	return out, nil
}

// sanitize applies strip_process_args and pid hashing to a copy of the labels.
func sanitize(in map[string]string, pid uint32, o FoldOptions) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	if o.StripArgs {
		delete(out, "process.command_line")
		if exe := out["process.executable"]; exe != "" {
			out["process.executable"] = path.Base(exe)
		}
	}
	if o.PlainPID {
		out["pid"] = fmt.Sprint(pid)
	} else {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", in["host"], pid)))
		out["pid"] = hex.EncodeToString(h[:6])
	}
	return out
}

type builder struct {
	kind   Kind
	start  time.Time
	dur    time.Duration
	nsPer  int64 // nanoseconds per CPU sample
	strs   []string
	strIdx map[string]int64
	locs   map[Frame]uint64
	locBuf []byte
	fnIdx  map[string]uint64
	fnBuf  []byte
	maps   map[string]uint64
	mapBuf []byte
	samps  []byte
}

func newBuilder(kind Kind, start time.Time, dur time.Duration, hz int) *builder {
	b := &builder{kind: kind, start: start, dur: dur, strIdx: map[string]int64{}, locs: map[Frame]uint64{},
		fnIdx: map[string]uint64{}, maps: map[string]uint64{}}
	if hz <= 0 {
		hz = 19
	}
	b.nsPer = int64(time.Second) / int64(hz)
	b.str("") // string 0 must be empty
	return b
}

func (b *builder) str(s string) int64 {
	if i, ok := b.strIdx[s]; ok {
		return i
	}
	i := int64(len(b.strs))
	b.strs = append(b.strs, s)
	b.strIdx[s] = i
	return i
}

func (b *builder) mapping(f Frame) uint64 {
	if f.Module == "" {
		return 0
	}
	key := f.Module + "\x00" + f.BuildID
	if id, ok := b.maps[key]; ok {
		return id
	}
	id := uint64(len(b.maps) + 1)
	b.maps[key] = id
	var m []byte
	m = protowire.AppendTag(m, 1, protowire.VarintType)
	m = protowire.AppendVarint(m, id)
	m = protowire.AppendTag(m, 5, protowire.VarintType)
	m = protowire.AppendVarint(m, uint64(b.str(f.Module)))
	if f.BuildID != "" {
		m = protowire.AppendTag(m, 6, protowire.VarintType)
		m = protowire.AppendVarint(m, uint64(b.str(f.BuildID)))
	}
	b.mapBuf = protowire.AppendTag(b.mapBuf, 3, protowire.BytesType)
	b.mapBuf = protowire.AppendBytes(b.mapBuf, m)
	return id
}

func (b *builder) function(name string) uint64 {
	if id, ok := b.fnIdx[name]; ok {
		return id
	}
	id := uint64(len(b.fnIdx) + 1)
	b.fnIdx[name] = id
	var f []byte
	f = protowire.AppendTag(f, 1, protowire.VarintType)
	f = protowire.AppendVarint(f, id)
	f = protowire.AppendTag(f, 2, protowire.VarintType)
	f = protowire.AppendVarint(f, uint64(b.str(name)))
	b.fnBuf = protowire.AppendTag(b.fnBuf, 5, protowire.BytesType)
	b.fnBuf = protowire.AppendBytes(b.fnBuf, f)
	return id
}

func (b *builder) location(f Frame) uint64 {
	if id, ok := b.locs[f]; ok {
		return id
	}
	id := uint64(len(b.locs) + 1)
	b.locs[f] = id
	var l []byte
	l = protowire.AppendTag(l, 1, protowire.VarintType)
	l = protowire.AppendVarint(l, id)
	if mid := b.mapping(f); mid != 0 {
		l = protowire.AppendTag(l, 2, protowire.VarintType)
		l = protowire.AppendVarint(l, mid)
	}
	l = protowire.AppendTag(l, 3, protowire.VarintType)
	l = protowire.AppendVarint(l, f.Addr)
	if f.Name != "" {
		var line []byte
		line = protowire.AppendTag(line, 1, protowire.VarintType)
		line = protowire.AppendVarint(line, b.function(f.Name))
		l = protowire.AppendTag(l, 4, protowire.BytesType)
		l = protowire.AppendBytes(l, line)
	}
	b.locBuf = protowire.AppendTag(b.locBuf, 4, protowire.BytesType)
	b.locBuf = protowire.AppendBytes(b.locBuf, l)
	return id
}

func (b *builder) add(e Entry, r Resolver, labels map[string]string) {
	var ids []uint64
	for _, a := range e.Kernel {
		ids = append(ids, b.location(r.Kernel(a)))
	}
	for _, a := range e.User {
		ids = append(ids, b.location(r.User(e.PID, a)))
	}
	if len(ids) == 0 {
		return
	}
	var s, packed []byte
	for _, id := range ids {
		packed = protowire.AppendVarint(packed, id)
	}
	s = protowire.AppendTag(s, 1, protowire.BytesType)
	s = protowire.AppendBytes(s, packed)
	var vals []byte
	if b.kind == CPU {
		vals = protowire.AppendVarint(vals, e.Value)
		vals = protowire.AppendVarint(vals, e.Value*uint64(b.nsPer))
	} else {
		vals = protowire.AppendVarint(vals, e.Value)
	}
	s = protowire.AppendTag(s, 2, protowire.BytesType)
	s = protowire.AppendBytes(s, vals)
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var l []byte
		l = protowire.AppendTag(l, 1, protowire.VarintType)
		l = protowire.AppendVarint(l, uint64(b.str(k)))
		l = protowire.AppendTag(l, 2, protowire.VarintType)
		l = protowire.AppendVarint(l, uint64(b.str(labels[k])))
		s = protowire.AppendTag(s, 3, protowire.BytesType)
		s = protowire.AppendBytes(s, l)
	}
	b.samps = protowire.AppendTag(b.samps, 2, protowire.BytesType)
	b.samps = protowire.AppendBytes(b.samps, s)
}

func valueType(typ, unit int64) []byte {
	var v []byte
	v = protowire.AppendTag(v, 1, protowire.VarintType)
	v = protowire.AppendVarint(v, uint64(typ))
	v = protowire.AppendTag(v, 2, protowire.VarintType)
	return protowire.AppendVarint(v, uint64(unit))
}

func (b *builder) gzip() ([]byte, error) {
	ns, count := b.str("nanoseconds"), b.str("count")
	var head []byte
	var period int64
	if b.kind == CPU {
		samples, cpu := b.str("samples"), b.str("cpu")
		for _, vt := range [][]byte{valueType(samples, count), valueType(cpu, ns)} {
			head = protowire.AppendTag(head, 1, protowire.BytesType)
			head = protowire.AppendBytes(head, vt)
		}
		period = b.nsPer
		head = appendPeriod(head, cpu, ns, period)
	} else {
		off := b.str(string(b.kind))
		head = protowire.AppendTag(head, 1, protowire.BytesType)
		head = protowire.AppendBytes(head, valueType(off, ns))
		head = appendPeriod(head, off, ns, 1)
	}
	var raw []byte
	raw = append(raw, head...) // sample_type (1) and period fields come first; order is irrelevant to readers
	raw = append(raw, b.samps...)
	raw = append(raw, b.mapBuf...)
	raw = append(raw, b.locBuf...)
	raw = append(raw, b.fnBuf...)
	for _, s := range b.strs {
		raw = protowire.AppendTag(raw, 6, protowire.BytesType)
		raw = protowire.AppendString(raw, s)
	}
	raw = protowire.AppendTag(raw, 9, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(b.start.UnixNano()))
	raw = protowire.AppendTag(raw, 10, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(b.dur.Nanoseconds()))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendPeriod(b []byte, typ, unit, period int64) []byte {
	b = protowire.AppendTag(b, 11, protowire.BytesType)
	b = protowire.AppendBytes(b, valueType(typ, unit))
	b = protowire.AppendTag(b, 12, protowire.VarintType)
	return protowire.AppendVarint(b, uint64(period))
}

// Poster uploads profiles to the gateway.
type Poster struct {
	Endpoint, Token string
	Client          *http.Client
}

// Post sends one profile; the caller counts and drops failures.
func (p Poster) Post(ctx context.Context, pr Profile) error {
	c := p.Client
	if c == nil {
		c = netguard.Guarded("agent", 30*time.Second)
	}
	q := url.Values{"service": {pr.Service}, "format": {"pprof"}, "source": {"ebpf"}, "sample_type": {string(pr.Kind)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint+"/v1/profiles?"+q.Encode(), bytes.NewReader(pr.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("profiles upload: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Guard keeps the module under its own CPU budget by halving the sample rate.
type Guard struct {
	Budget float64
	Rate   int
}

// Observe takes the agent's CPU seconds and the wall seconds since the last call. It returns
// true when it halved Rate.
func (g *Guard) Observe(cpuSec, wallSec float64) bool {
	if wallSec <= 0 || g.Rate <= 1 || cpuSec/wallSec <= g.Budget {
		return false
	}
	g.Rate /= 2
	return true
}
