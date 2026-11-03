package net

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type rec struct {
	sums   map[string]float64
	gauges map[string]float64
	logs   int
}

func newRec() *rec { return &rec{sums: map[string]float64{}, gauges: map[string]float64{}} }

func (r *rec) Gauge(n, _ string, v float64, _ map[string]string, _ time.Time) { r.gauges[n] = v }
func (r *rec) Sum(n, _ string, v float64, a map[string]string, _ time.Time) {
	r.sums[n+"|"+a["src.workload"]+">"+a["dst.workload"]+":"+a["server.port"]] = v
	r.sums[n] = v
}
func (r *rec) Log(string, string, map[string]string, time.Time) { r.logs++ }

type fakeRes struct{}

func (fakeRes) Workload(pid uint32, _ uint64) string {
	return map[uint32]string{1: "web", 2: "api"}[pid]
}
func (fakeRes) Listener(port uint16) string { return map[uint16]string{8080: "api"}[port] }
func (fakeRes) IsLocal(a netip.Addr) bool   { return a.IsLoopback() || a.String() == "10.0.0.9" }

func TestAggregatesPerEdgeAndSkipsLocalPassive(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	ag := NewAggregator(fakeRes{})
	active := Conn{Active: true, PID: 1, Src: lo, Dst: lo, LPort: 40000, RPort: 8080, BytesSent: 100, BytesRecv: 900, Retrans: 2, SRTTus: 2000, ConnectNs: 1_000_000}
	ag.Add(active)
	ag.Add(active)
	// The twin the server side reports for the same loopback connection must not double count.
	ag.Add(Conn{PID: 0, Src: lo, Dst: lo, LPort: 8080, RPort: 40000, BytesSent: 900, BytesRecv: 100})
	ag.Add(Conn{Active: true, PID: 1, Src: lo, Dst: netip.MustParseAddr("203.0.113.7"), RPort: 443, Failed: true})
	out := newRec()
	ag.Flush(out, time.Now())
	if got := out.sums["wt.net.tcp.bytes_received|web>api:8080"]; got != 1800 {
		t.Fatalf("bytes_received web>api = %v", got)
	}
	if got := out.sums["wt.net.tcp.connections|web>api:8080"]; got != 2 {
		t.Fatalf("connections = %v", got)
	}
	if got := out.sums["wt.net.tcp.connect_failures|web>203.0.113.7:443"]; got != 1 {
		t.Fatalf("connect failures = %v", got)
	}
	if out.gauges["wt.net.tcp.rtt"] != 0.002 || out.logs != 1 {
		t.Fatalf("rtt %v logs %d", out.gauges["wt.net.tcp.rtt"], out.logs)
	}
	// Nothing changed: the next flush exports no edge again.
	out2 := newRec()
	ag.Flush(out2, time.Now())
	if len(out2.sums) != 0 {
		t.Fatalf("unchanged edges re-exported: %v", out2.sums)
	}
}

func TestPassiveRemoteConnectionNamesListener(t *testing.T) {
	ag := NewAggregator(fakeRes{})
	ag.Add(Conn{Src: netip.MustParseAddr("10.0.0.9"), Dst: netip.MustParseAddr("198.51.100.4"), LPort: 8080, RPort: 51000, BytesRecv: 5})
	out := newRec()
	ag.Flush(out, time.Now())
	if out.sums["wt.net.tcp.bytes_received|198.51.100.4>api:8080"] != 5 {
		t.Fatalf("got %v", out.sums)
	}
}

func dnsPacketBytes(t *testing.T, id uint16, resp bool, rc dnsmessage.RCode) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: resp, RCode: rc},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDNSLatencyAndFailures(t *testing.T) {
	d := NewDNSTracker()
	t0 := time.Now()
	q, _ := ParseDNS(dnsPacketBytes(t, 7, false, 0))
	r, ok := ParseDNS(dnsPacketBytes(t, 7, true, dnsmessage.RCodeNameError))
	if !ok || q.Name != "example.com" || r.Type != "A" || r.RCode != "NameError" {
		t.Fatalf("q=%+v r=%+v", q, r)
	}
	d.Observe(q, 5353, t0)
	d.Observe(r, 5353, t0.Add(20*time.Millisecond))
	out := newRec()
	d.Flush(out, t0)
	if out.sums["wt.net.dns.queries"] != 1 || out.gauges["wt.net.dns.latency"] < 0.019 || out.logs != 1 {
		t.Fatalf("sums %v gauges %v logs %d", out.sums, out.gauges, out.logs)
	}
	if _, ok := ParseDNS([]byte("not dns")); ok {
		t.Fatal("garbage parsed as DNS")
	}
}

func TestConfigDefaultsAndDisabled(t *testing.T) {
	c, err := ParseConfig(nil)
	if err != nil || c.Enabled || c.MaxEventsPerSec != 20_000 || !c.WantDNS() {
		t.Fatalf("%+v %v", c, err)
	}
	if w, _ := c.Window(); w != 10*time.Second {
		t.Fatalf("window %v", w)
	}
	for _, bad := range []string{`{"ring_buffer_kb": 100}`, `{"interval": "100ms"}`, `{"bogus": 1}`} {
		if _, err := ParseConfig(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

type labelRes struct{ fakeRes }

func (labelRes) Labels(w string) map[string]string {
	return map[string]map[string]string{"shop/cart-1": {"k8s.pod.name": "cart-1", "k8s.workload": "deployment/cart"}}[w]
}
func (labelRes) Workload(uint32, uint64) string { return "shop/cart-1" }

type attrRec struct{ attrs []map[string]string }

func (r *attrRec) Gauge(string, string, float64, map[string]string, time.Time) {}
func (r *attrRec) Sum(_, _ string, _ float64, a map[string]string, _ time.Time) {
	r.attrs = append(r.attrs, a)
}
func (r *attrRec) Log(string, string, map[string]string, time.Time) {}

func TestFlowEdgesCarryPodAttributes(t *testing.T) {
	ag := NewAggregator(labelRes{})
	ag.Add(Conn{Active: true, PID: 5, Src: netip.MustParseAddr("10.0.0.9"), Dst: netip.MustParseAddr("10.1.0.4"), RPort: 5432})
	var r attrRec
	ag.Flush(&r, time.Now())
	if len(r.attrs) == 0 || r.attrs[0]["src.k8s.pod.name"] != "cart-1" || r.attrs[0]["src.k8s.workload"] != "deployment/cart" {
		t.Fatalf("attrs %v", r.attrs)
	}
	if _, ok := r.attrs[0]["dst.k8s.pod.name"]; ok {
		t.Fatal("a remote peer has no pod labels")
	}
}
