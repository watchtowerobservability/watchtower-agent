package snmp

import (
	"slices"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func ifPDUs(in uint32, ticks uint32) []gosnmp.SnmpPDU {
	tb := "1.3.6.1.2.1.2.2.1."
	return []gosnmp.SnmpPDU{
		pdu(tb+"2.7", gosnmp.OctetString, []byte("ge1")),
		pdu(tb+"5.7", gosnmp.Gauge32, uint32(1000000000)), // 1 Gbit/s: at most 125 MB/s
		pdu(tb+"10.7", gosnmp.Counter32, in),
		pdu(sysUpTime, gosnmp.TimeTicks, ticks),
	}
}

func ifMib(t *testing.T) []Manifest {
	t.Helper()
	all, err := Manifests("")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := pick(all, []string{"if-mib"})
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func rateOf(rates *Rates, ms []Manifest, in, ticks uint32, at time.Time) (*sink.Recorder, bool) {
	rec := &sink.Recorder{}
	emit(rec, rates, "sw", ms, ifPDUs(in, ticks), at)
	_, ok := find(rec, "snmp.interface.io.rate")
	return rec, ok
}

func TestCounterResetBeyondLineRateIsNotASpike(t *testing.T) {
	ms, rates, t0 := ifMib(t), &Rates{}, time.Unix(1000, 0)
	if _, ok := rateOf(rates, ms, 500000000, 1000, t0); ok {
		t.Fatal("first poll has no rate")
	}
	// The counter fell from 5e8 to 1e4: read as a wrap that is 3.8e8 B/s, above a 1 Gbit/s link.
	if _, ok := rateOf(rates, ms, 10000, 2000, t0.Add(10*time.Second)); ok {
		t.Fatal("a rate above the interface speed must be dropped as a reset")
	}
	rec, ok := rateOf(rates, ms, 10000+1250000, 3000, t0.Add(20*time.Second))
	if !ok {
		t.Fatal("the next interval re-baselined and must report")
	}
	want(t, rec, 125000, "snmp.interface.io.rate", "network.io.direction", "receive", "snmp.index", "7", "snmp.if_descr", "ge1")
}

func TestSysUpTimeBackwardsDropsRates(t *testing.T) {
	ms, rates, t0 := ifMib(t), &Rates{}, time.Unix(1000, 0)
	rateOf(rates, ms, 1000, 100000, t0)
	if _, ok := rateOf(rates, ms, 1000, 100000, t0.Add(10*time.Second)); !ok {
		t.Fatal("steady device reports")
	}
	// Reboot: uptime went back, and the counter (plausibly) went on from a small value.
	if _, ok := rateOf(rates, ms, 5000, 500, t0.Add(20*time.Second)); ok {
		t.Fatal("no rate across a restart")
	}
	rec, ok := rateOf(rates, ms, 15000, 1500, t0.Add(30*time.Second))
	if !ok {
		t.Fatal("rate resumes after the re-baseline")
	}
	want(t, rec, 1000, "snmp.interface.io.rate")
}

func TestRowsWithTheSameNameKeepTheirIndex(t *testing.T) {
	all, _ := Manifests("")
	ms, _ := pick(all, []string{"host-resources-mib"})
	tb := "1.3.6.1.2.1.25.3.3.1.2."
	rec := &sink.Recorder{}
	emit(rec, &Rates{}, "srv", ms, []gosnmp.SnmpPDU{pdu(tb+"196608", gosnmp.Integer, 10), pdu(tb+"196609", gosnmp.Integer, 90)}, time.Now())
	want(t, rec, 10, "snmp.processor.load", "snmp.index", "196608")
	want(t, rec, 90, "snmp.processor.load", "snmp.index", "196609")
}

func TestWalksCoverOnlyUsedColumnsAndTruncationIsCounted(t *testing.T) {
	all, _ := Manifests("")
	var ifTable Table
	for _, tb := range all["if-mib"].Tables {
		if tb.Name == "ifTable" {
			ifTable = tb
		}
	}
	cols := ifTable.columnOIDs()
	if slices.Contains(cols, "1.3.6.1.2.1.2.2.1.1") || slices.Contains(cols, "1.3.6.1.2.1.2.2.1") {
		t.Fatalf("unused columns or the whole table are walked: %v", cols)
	}
	for _, want := range []string{"1.3.6.1.2.1.2.2.1.10", "1.3.6.1.2.1.2.2.1.5", "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.1"} {
		if !slices.Contains(cols, want) {
			t.Fatalf("column %s missing from %v", want, cols)
		}
	}
	var rates Rates
	t0 := time.Unix(0, 0)
	n1, log1 := rates.Truncated("sw", "ifTable", t0)
	n2, log2 := rates.Truncated("sw", "ifTable", t0.Add(time.Minute))
	_, log3 := rates.Truncated("sw", "ifTable", t0.Add(2*time.Hour))
	if n1 != 1 || n2 != 2 || !log1 || log2 || !log3 {
		t.Fatalf("counts %v %v, logs %v %v %v: want 1 2 and log once per hour", n1, n2, log1, log2, log3)
	}
}

func TestHighValueTablesAreWalkedFirst(t *testing.T) {
	all, _ := Manifests("")
	ms, _ := pick(all, nil)
	var jobs []walkJob
	for _, m := range ms {
		for _, tb := range m.Tables {
			for _, oid := range tb.columnOIDs() {
				jobs = append(jobs, walkJob{tb.Name, oid, tb.Priority})
			}
		}
	}
	// the same ordering gather applies
	slices.SortStableFunc(jobs, func(a, b walkJob) int { return b.prio - a.prio })
	if jobs[0].prio < 2 || jobs[len(jobs)-1].prio >= 2 {
		t.Fatalf("priority order broken: first %+v last %+v", jobs[0], jobs[len(jobs)-1])
	}
	var ifXFirst, hrFirst = -1, -1
	for i, j := range jobs {
		if j.table == "ifXTable" && ifXFirst < 0 {
			ifXFirst = i
		}
		if j.table == "hrStorageTable" && hrFirst < 0 {
			hrFirst = i
		}
	}
	if ifXFirst < 0 || hrFirst < 0 || ifXFirst > hrFirst {
		t.Fatalf("ifXTable (%d) must come before hrStorageTable (%d)", ifXFirst, hrFirst)
	}
}
