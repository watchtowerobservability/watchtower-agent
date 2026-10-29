package snmp

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const sysUpTime = "1.3.6.1.2.1.1.3.0"

type walkJob struct {
	table, oid string
	prio       int
}

// gather reads everything the manifests name: sysUpTime and the scalars first, then one walk per
// used column, the high-priority tables before the others so a cut-off falls on the cheap ones.
// It returns the names of the tables whose walks were cut by the varbind cap, and fails only
// when nothing could be read.
func gather(g *gosnmp.GoSNMP, ms []Manifest) ([]gosnmp.SnmpPDU, []string, error) {
	budget := MaxVarbinds
	scalars := []string{"." + sysUpTime}
	var jobs []walkJob
	for _, m := range ms {
		for _, s := range m.Scalars {
			scalars = append(scalars, "."+norm(s.OID))
		}
		for _, tb := range m.Tables {
			for _, oid := range tb.columnOIDs() {
				jobs = append(jobs, walkJob{tb.Name, oid, tb.Priority})
			}
		}
	}
	sort.SliceStable(jobs, func(i, j int) bool { return jobs[i].prio > jobs[j].prio })

	var first error
	out, err := get(g, scalars)
	if err != nil {
		first = err
	}
	var cut []string
	seen := map[string]bool{}
	for _, j := range jobs {
		ps, capped, err := walkOne(g, j.oid, &budget)
		out = append(out, ps...)
		if err != nil && first == nil {
			first = err
		}
		if capped && !seen[j.table] {
			seen[j.table] = true
			cut = append(cut, j.table)
		}
	}
	if len(out) == 0 {
		return nil, cut, first
	}
	return out, cut, nil
}

// PollTarget polls one device once and writes its metrics.
func PollTarget(ctx context.Context, t Target, ms []Manifest, rates *Rates, out sink.Sink, at time.Time) error {
	up := func(v float64) {
		out.Gauge("snmp.device.up", "1", v, map[string]string{"snmp.device": t.Name}, at)
	}
	g, err := t.open(ctx)
	if err == nil {
		defer g.Conn.Close()
		var pdus []gosnmp.SnmpPDU
		var cut []string
		if pdus, cut, err = gather(g, ms); err == nil {
			if ctx.Err() != nil { // the deadline already reported this device as down
				return ctx.Err()
			}
			up(1)
			for _, table := range cut {
				total, logNow := rates.Truncated(t.Name, table, at)
				out.Sum("wt.agent.snmp.truncated_total", "{walk}", total, map[string]string{"device": t.Name, "table": table}, at)
				if logNow {
					slog.Warn("snmp walk cut at the varbind cap", "device", t.Name, "table", table, "cap", MaxVarbinds)
				}
			}
			emit(out, rates, t.Name, ms, pdus, at)
			return nil
		}
		err = t.scrub(err)
	}
	up(0)
	return err
}
