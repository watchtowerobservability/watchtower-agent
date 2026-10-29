package snmp

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// emit turns the varbinds read for the manifests into metrics. It touches no network.
func emit(out sink.Sink, rates *Rates, dev string, ms []Manifest, pdus []gosnmp.SnmpPDU, at time.Time) {
	byName := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for _, p := range pdus {
		byName[norm(p.Name)] = p
	}
	base := map[string]string{"snmp.device": dev}
	// A restarted device starts all its counters over: forget the baselines so this poll only
	// re-baselines and no rate is reported for the interval.
	if up, ok := byName[sysUpTime]; ok {
		if ticks, ok := unsigned(up.Value); ok && rates.WentBack(dev, ticks) {
			rates.Forget(dev)
		}
	}
	for _, m := range ms {
		for _, s := range m.Scalars {
			if p, ok := byName[norm(s.OID)]; ok {
				emitItem(out, rates, dev+"|"+norm(s.OID), s, p, 1, 0, base, at)
			}
		}
		for _, tb := range m.Tables {
			rows, idxs := rowsOf(pdus, tb.OID)
			if tb.Sensor {
				emitSensors(out, dev, tb, rows, idxs, pdus, at)
				continue
			}
			extras := extraLabels(tb, pdus)
			for _, idx := range idxs {
				row := rows[idx]
				// snmp.index (ifIndex, hrDeviceIndex, ...) keeps rows with equal names apart.
				attrs := sink.With(base, "snmp.index", idx)
				if tb.LabelAttr != "" {
					label := idx
					if p, ok := row[tb.LabelCol]; ok && tb.LabelCol != "" {
						label = pduString(p)
					}
					attrs[tb.LabelAttr] = label
				}
				for i, e := range tb.Extra {
					if v := extras[i][idx]; v != "" {
						attrs[e.Attr] = v
					}
				}
				var limit float64 // bytes/s the interface can carry, 0 when unknown
				if sp, ok := numeric(row[tb.SpeedCol]); ok && sp > 0 {
					scale := tb.SpeedScale
					if scale == 0 {
						scale = 1
					}
					limit = sp * scale / 8 * speedSlack
				}
				for _, it := range tb.Items {
					p, ok := row[it.Col]
					if !ok {
						continue
					}
					mul := 1.0
					if it.MulCol != "" {
						f, ok := numeric(row[it.MulCol])
						if !ok {
							continue
						}
						mul = f
					}
					lim := 0.0
					if it.SpeedLimit {
						lim = limit
					}
					emitItem(out, rates, dev+"|"+tb.OID+"|"+it.Col+"|"+idx, it, p, mul, lim, attrs, at)
				}
			}
		}
	}
}

// speedSlack lets a measured rate exceed the nominal line rate a little (timing jitter).
const speedSlack = 1.5

// extraLabels reads the Extra columns of a table: index -> value, one map per Extra.
func extraLabels(tb Table, pdus []gosnmp.SnmpPDU) []map[string]string {
	out := make([]map[string]string, len(tb.Extra))
	for i, e := range tb.Extra {
		out[i] = map[string]string{}
		for _, p := range pdus {
			if idx := suffix(p.Name, norm(e.OID)); idx != "" {
				out[i][idx] = pduString(p)
			}
		}
	}
	return out
}

// rowsOf groups the varbinds below a table OID by row index then column.
func rowsOf(pdus []gosnmp.SnmpPDU, tableOID string) (map[string]map[string]gosnmp.SnmpPDU, []string) {
	rows := map[string]map[string]gosnmp.SnmpPDU{}
	for _, p := range pdus {
		col, idx, ok := strings.Cut(suffix(p.Name, tableOID), ".")
		if !ok {
			continue
		}
		if rows[idx] == nil {
			rows[idx] = map[string]gosnmp.SnmpPDU{}
		}
		rows[idx][col] = p
	}
	idxs := make([]string, 0, len(rows))
	for k := range rows {
		idxs = append(idxs, k)
	}
	sort.Strings(idxs)
	return rows, idxs
}

// emitItem writes one value. limit > 0 is the largest plausible rate of a counter: a bigger one
// is a counter reset (the baseline is already updated), so nothing is reported.
func emitItem(out sink.Sink, rates *Rates, key string, it Item, p gosnmp.SnmpPDU, mul, limit float64, attrs map[string]string, at time.Time) {
	scale := it.Scale
	if scale == 0 {
		scale = 1
	}
	if len(it.Attrs) > 0 {
		merged := sink.With(attrs)
		for k, v := range it.Attrs {
			merged[k] = v
		}
		attrs = merged
	}
	var v float64
	if it.Kind == "counter" {
		raw, ok := unsigned(p.Value)
		if !ok {
			return
		}
		bits := 64
		if p.Type == gosnmp.Counter32 {
			bits = 32
		}
		rate, ok := rates.Update(key, raw, bits, at)
		if !ok || limit > 0 && rate > limit {
			return
		}
		v = rate * scale
	} else {
		n, ok := numeric(p)
		if !ok {
			return
		}
		v = n * scale * mul
	}
	out.Gauge(it.Metric, it.Unit, v, attrs, at)
}

// sensorKinds maps ENTITY-SENSOR-MIB EntitySensorDataType to a metric.
// hwType is the OTel hw.type enum value, empty where the semconv has none (then only
// snmp.sensor_type says what the sensor is).
var sensorKinds = map[int]struct{ metric, unit, kind, hwType string }{
	3: {"hw.voltage", "V", "voltage_ac", "voltage"}, 4: {"hw.voltage", "V", "voltage", "voltage"},
	5: {"hw.current", "A", "current", ""}, 6: {"hw.power", "W", "power", ""}, 7: {"hw.frequency", "Hz", "frequency", ""},
	8: {"hw.temperature", "Cel", "temperature", "temperature"}, 9: {"hw.humidity", "%", "humidity", ""},
	10: {"hw.fan.speed", "rpm", "fan", "fan"},
}

func emitSensors(out sink.Sink, dev string, tb Table, rows map[string]map[string]gosnmp.SnmpPDU, idxs []string, pdus []gosnmp.SnmpPDU, at time.Time) {
	names := map[string]string{}
	if tb.NameOID != "" {
		for _, p := range pdus {
			if idx := suffix(p.Name, tb.NameOID); idx != "" {
				names[idx] = pduString(p)
			}
		}
	}
	for _, idx := range idxs {
		row := rows[idx]
		typ, ok1 := numeric(row["1"])
		scale, ok2 := numeric(row["2"])
		prec, _ := numeric(row["3"])
		raw, ok4 := numeric(row["4"])
		if st, ok := numeric(row["5"]); ok && st != 1 { // only sensors that report ok
			continue
		}
		k, known := sensorKinds[int(typ)]
		if !ok1 || !ok2 || !ok4 || !known {
			continue
		}
		v := raw * math.Pow(10, (scale-9)*3-prec)
		attrs := map[string]string{"snmp.device": dev, "snmp.index": idx, "hw.id": idx, "snmp.sensor_type": k.kind}
		if k.hwType != "" {
			attrs["hw.type"] = k.hwType
		}
		if n := names[idx]; n != "" {
			attrs["hw.name"] = n
		}
		out.Gauge(k.metric, k.unit, v, attrs, at)
	}
}

func numeric(p gosnmp.SnmpPDU) (float64, bool) {
	switch v := p.Value.(type) {
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	}
	if u, ok := unsigned(p.Value); ok {
		return float64(u), true
	}
	return 0, false
}

func unsigned(x any) (uint64, bool) {
	switch v := x.(type) {
	case uint:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int:
		return uint64(max(v, 0)), v >= 0
	}
	return 0, false
}

// pduString renders a varbind value for a label or a log attribute.
func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		if utf8.Valid(v) && strings.IndexFunc(string(v), func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
			return string(v)
		}
		return "0x" + hex.EncodeToString(v)
	case string:
		return v
	case nil:
		return ""
	}
	return fmt.Sprint(p.Value)
}
