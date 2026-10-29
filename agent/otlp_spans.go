package main

import (
	"context"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

const maxBufferedSpans = 20_000

type spanBatch struct {
	res   map[string]string
	spans []*tracepb.Span
}

// AddSpans buffers spans for POST /v1/traces. res (service.name of the observed process) is
// merged over the agent's own resource. The oldest spans are dropped past maxBufferedSpans.
func (o *OTLP) AddSpans(res map[string]string, spans []*tracepb.Span) {
	if len(spans) == 0 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.spans = append(o.spans, spanBatch{res: res, spans: spans})
	n := 0
	for _, b := range o.spans {
		n += len(b.spans)
	}
	for n > maxBufferedSpans && len(o.spans) > 0 {
		n -= len(o.spans[0].spans)
		o.dropped += len(o.spans[0].spans)
		o.spans = o.spans[1:]
	}
}

func (o *OTLP) takeSpans() []spanBatch {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.spans
	o.spans = nil
	return s
}

// TracesRequest groups batches into one ResourceSpans per distinct resource.
func (o *OTLP) TracesRequest(batches []spanBatch) *coltrace.ExportTraceServiceRequest {
	idx := map[string]*tracepb.ResourceSpans{}
	req := &coltrace.ExportTraceServiceRequest{}
	for _, b := range batches {
		k := resKey(b.res)
		rs := idx[k]
		if rs == nil {
			rs = &tracepb.ResourceSpans{Resource: o.resourceWith(b.res), ScopeSpans: []*tracepb.ScopeSpans{{}}}
			idx[k] = rs
			req.ResourceSpans = append(req.ResourceSpans, rs)
		}
		rs.ScopeSpans[0].Spans = append(rs.ScopeSpans[0].Spans, b.spans...)
	}
	return req
}

// flushSpans posts the spans; a failed post drops them (spans are best effort, never requeued
// so a down gateway cannot grow memory).
func (o *OTLP) flushSpans(ctx context.Context, batches []spanBatch) error {
	if len(batches) == 0 {
		return nil
	}
	_, err := o.post(ctx, "/v1/traces", o.TracesRequest(batches))
	return err
}
