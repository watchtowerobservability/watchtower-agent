package main

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func TestExportSurvivesInvalidUTF8(t *testing.T) {
	o := NewOTLP("http://127.0.0.1:1", "wti_x_y", map[string]string{"host.name": "h\xff"})
	bad := "bad\xff\xfe"
	o.Gauge(bad, "u\xff", 1, map[string]string{"k\xff": "v\xc3"}, time.Now())
	o.Log("INFO", bad, map[string]string{"a": bad}, time.Now())
	if _, err := proto.Marshal(o.MetricsRequest(o.points)); err != nil {
		t.Fatalf("metrics must marshal: %v", err)
	}
	if _, err := proto.Marshal(o.LogsRequest(o.logs)); err != nil {
		t.Fatalf("logs must marshal: %v", err)
	}
}

func TestExportBufferBoundedInBytesAndSplit(t *testing.T) {
	o := NewOTLP("http://127.0.0.1:1", "wti_x_y", nil)
	body := strings.Repeat("x", 200<<10)
	for range 100 { // 20 MB offered, 8 MiB kept
		o.Log("INFO", body, nil, time.Now())
	}
	if o.bytes > maxBufBytes+len(body)+1024 {
		t.Fatalf("buffer is %d bytes", o.bytes)
	}
	chunks := split(o.logs, func(r logRec) int { return r.size }, chunkBytes)
	if len(chunks) < 2 {
		t.Fatalf("a large buffer must split into several requests, got %d", len(chunks))
	}
	total := 0
	for _, c := range chunks {
		sum := 0
		for _, r := range c {
			sum += r.size
		}
		if sum > chunkBytes+len(body)+1024 {
			t.Fatalf("chunk of %d bytes", sum)
		}
		total += len(c)
	}
	if total != len(o.logs) {
		t.Fatalf("split lost records: %d of %d", total, len(o.logs))
	}
}
