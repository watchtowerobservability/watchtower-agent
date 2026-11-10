package relay

import (
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

func metricEvents(name string, mt *metricspb.Metric, svc string, res map[string]string) []Event {
	var out []Event
	pt := func(n, typ string, ts uint64, v float64, kv []*commonpb.KeyValue) {
		out = append(out, Event{Kind: "metric", Time: nanos(ts), Name: n, Service: svc, Value: &v, MetricType: typ, Attrs: merged(res, kv)})
	}
	num := func(typ string, dps []*metricspb.NumberDataPoint) {
		for _, d := range dps {
			v := d.GetAsDouble()
			if _, ok := d.Value.(*metricspb.NumberDataPoint_AsInt); ok {
				v = float64(d.GetAsInt())
			}
			pt(name, typ, d.TimeUnixNano, v, d.Attributes)
		}
	}
	switch d := mt.Data.(type) {
	case *metricspb.Metric_Gauge:
		num("gauge", d.Gauge.DataPoints)
	case *metricspb.Metric_Sum:
		num("count", d.Sum.DataPoints)
	case *metricspb.Metric_Histogram:
		for _, p := range d.Histogram.DataPoints {
			pt(name+".count", "count", p.TimeUnixNano, float64(p.Count), p.Attributes)
			pt(name+".sum", "count", p.TimeUnixNano, p.GetSum(), p.Attributes)
		}
	case *metricspb.Metric_Summary:
		for _, p := range d.Summary.DataPoints {
			pt(name+".count", "count", p.TimeUnixNano, float64(p.Count), p.Attributes)
			pt(name+".sum", "count", p.TimeUnixNano, p.Sum, p.Attributes)
		}
	}
	return out
}
