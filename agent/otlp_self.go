package main

import "sync/atomic"

// exportStats are the agent's own delivery counters (ING-025), sent by the `agent` module as
// wt_agent_export_* series next to wt_agent_info so a stalled or lossy agent shows up in the
// product itself, not only in its log.
type exportStats struct {
	sent, failed, rejected, dropped, bytes atomic.Int64
}

// SelfStats are cumulative counters (series name to value) plus the bytes waiting to be sent.
func (o *OTLP) SelfStats() map[string]float64 {
	s := &o.stats
	return map[string]float64{
		"wt_agent_export_batches_sent_total":     float64(s.sent.Load()),
		"wt_agent_export_batches_failed_total":   float64(s.failed.Load()),
		"wt_agent_export_batches_rejected_total": float64(s.rejected.Load()),
		"wt_agent_export_records_dropped_total":  float64(s.dropped.Load()),
		"wt_agent_export_bytes_sent_total":       float64(s.bytes.Load()),
		"wt_agent_export_buffered_bytes":         float64(o.Buffered()),
	}
}

// selfStater is the optional exporter interface the `agent` module reads.
type selfStater interface{ SelfStats() map[string]float64 }

// SelfStats passes the inner exporter's counters through a tap (nil when it keeps none).
func (e *tapExporter) SelfStats() map[string]float64 {
	if s, ok := e.Exporter.(selfStater); ok {
		return s.SelfStats()
	}
	return nil
}
