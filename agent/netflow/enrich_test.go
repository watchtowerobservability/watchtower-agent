package netflow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestASAndGeoEnrich(t *testing.T) {
	lookups := 0
	e := NewEnricher(
		[]PrefixInfo{
			{netip.MustParsePrefix("8.0.0.0/8"), 3356, "US", ""},
			{netip.MustParsePrefix("8.8.8.0/24"), 15169, "US", ""},
			{netip.MustParsePrefix("2001:db8::/32"), 64500, "DE", ""},
		},
		map[string]map[uint32]string{"10.0.0.1": {1: "Gi0/1", 2: "Gi0/2"}},
		func(netip.Addr) string { lookups++; return "dns.google" },
	)
	agg := NewAggregator()
	agg.Enricher = e
	at := time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC)
	for range 3 {
		agg.Add(Flow{Exporter: "10.0.0.1", Src: netip.MustParseAddr("10.1.1.1"), Dst: netip.MustParseAddr("8.8.8.8"),
			Proto: 6, InIf: 1, OutIf: 2, Bytes: 10, Packets: 1}, at)
	}
	var rec sink.Recorder
	agg.Flush(at, true, &rec)
	if len(rec.Samples) != 1 {
		t.Fatalf("records %d", len(rec.Samples))
	}
	a := rec.Samples[0].Attrs
	if a["flow.dst_asn"] != "15169" || a["flow.dst_country"] != "US" || a["flow.dst_host"] != "dns.google" {
		t.Fatalf("dst enrichment %v", a)
	}
	if _, ok := a["flow.src_asn"]; ok {
		t.Fatalf("private source got an AS: %v", a)
	}
	if a["flow.in_if_name"] != "Gi0/1" || a["flow.out_if_name"] != "Gi0/2" {
		t.Fatalf("interface names %v", a)
	}
	if lookups != 2 { // one per distinct address, cached after
		t.Fatalf("rdns lookups %d", lookups)
	}
	var none *Enricher
	none.Apply(a, "x", Row{}) // nil is a no-op
}

func TestCrossZone(t *testing.T) {
	e := NewEnricher([]PrefixInfo{
		{Prefix: netip.MustParsePrefix("10.0.1.0/24"), Zone: "us-east-1a"},
		{Prefix: netip.MustParsePrefix("10.0.2.0/24"), Zone: "us-east-1b"},
	}, nil, nil)
	a := map[string]string{}
	e.Apply(a, "x", Row{Key: Key{Src: netip.MustParseAddr("10.0.1.5"), Dst: netip.MustParseAddr("10.0.2.9")}})
	if a["flow.cross_zone"] != "true" || a["flow.src_zone"] != "us-east-1a" {
		t.Fatalf("%v", a)
	}
	if _, ok := a["flow.src_asn"]; ok {
		t.Fatal("zone-only prefix must not set an AS")
	}
}
