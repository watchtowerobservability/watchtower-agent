package main

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestHoistedAttrsGroupByResource(t *testing.T) {
	o := NewOTLP("http://127.0.0.1:1", "wti_x_y", map[string]string{"host.name": "n1"})
	h := sink.Hoist(o)
	at := time.Now()
	h.Gauge("k8s.pod.phase", "", 2, map[string]string{"resource.k8s.pod.uid": "a", "resource.host.name": "n2", "x": "1"}, at)
	h.Gauge("k8s.pod.phase", "", 2, map[string]string{"resource.k8s.pod.uid": "b"}, at)
	h.Gauge("k8s.pod.phase", "", 2, map[string]string{"resource.k8s.pod.uid": "a"}, at)
	req := o.MetricsRequest(o.points)
	if len(req.ResourceMetrics) != 3 {
		t.Fatalf("want one resource per distinct set, got %d", len(req.ResourceMetrics))
	}
	first := req.ResourceMetrics[0]
	got := map[string]string{}
	for _, kv := range first.Resource.Attributes {
		got[kv.Key] = kv.Value.GetStringValue()
	}
	if got["host.name"] != "n2" || got["k8s.pod.uid"] != "a" {
		t.Fatalf("resource override failed: %v", got)
	}
	dp := first.ScopeMetrics[0].Metrics[0].GetGauge().DataPoints[0]
	if len(dp.Attributes) != 1 || dp.Attributes[0].Key != "x" {
		t.Fatalf("point keeps only its own attributes: %v", dp.Attributes)
	}
}

// Only the Kubernetes collectors (through Hoist) can name the resource: the same keys sent
// straight to the exporter, as a scrape or any other module does, stay point attributes.
func TestPlainAttrsNeverReachTheResource(t *testing.T) {
	o := NewOTLP("http://127.0.0.1:1", "wti_x_y", map[string]string{"host.name": "n1"})
	o.Gauge("app_up", "", 1, map[string]string{"resource.host.name": "db-prod-1", "resource.k8s.deployment.uid": "victim"}, time.Now())
	o.Log("INFO", "x", map[string]string{"resource.host.name": "db-prod-1"}, time.Now())
	m := o.MetricsRequest(o.points)
	if len(m.ResourceMetrics) != 1 {
		t.Fatalf("one resource expected, got %d", len(m.ResourceMetrics))
	}
	for _, kv := range m.ResourceMetrics[0].Resource.Attributes {
		if kv.Key == "k8s.deployment.uid" || (kv.Key == "host.name" && kv.Value.GetStringValue() != "n1") {
			t.Fatalf("forged resource attribute %s=%s", kv.Key, kv.Value.GetStringValue())
		}
	}
	l := o.LogsRequest(o.logs)
	for _, kv := range l.ResourceLogs[0].Resource.Attributes {
		if kv.Key == "host.name" && kv.Value.GetStringValue() != "n1" {
			t.Fatal("forged log resource")
		}
	}
}

func TestLogsGroupByResource(t *testing.T) {
	o := NewOTLP("http://127.0.0.1:1", "wti_x_y", nil)
	h := sink.Hoist(o)
	h.Log("INFO", "a", map[string]string{"resource.k8s.pod.uid": "a"}, time.Now())
	h.Log("INFO", "b", map[string]string{"resource.k8s.pod.uid": "b", "k": "v"}, time.Now())
	if req := o.LogsRequest(o.logs); len(req.ResourceLogs) != 2 {
		t.Fatalf("got %d resources", len(req.ResourceLogs))
	}
}
