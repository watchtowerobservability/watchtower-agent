package cloud

import (
	"encoding/json"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestCloudRunPresetExpandsOnce(t *testing.T) {
	got := expandPresets(gcpPresets, []string{"run.googleapis.com/request_count"}, []string{"cloud_run", "unknown"})
	if len(got) != len(gcpPresets["cloud_run"]) || got[0] != "run.googleapis.com/request_count" {
		t.Fatalf("%v", got)
	}
}

func TestCloudRunSeriesGetFaaSResource(t *testing.T) {
	g := &gcpPull{c: gcpConfig{Project: "p1"}}
	var ts []gcpSeries
	err := json.Unmarshal([]byte(`[{"metric":{"type":"run.googleapis.com/request_latencies"},
		"resource":{"type":"cloud_run_revision","labels":{"service_name":"checkout","revision_name":"checkout-00042","location":"europe-west1"}},
		"points":[{"interval":{"endTime":"2026-10-30T10:00:00Z"},"value":{"distributionValue":{"count":"4","mean":12.5}}}]}]`), &ts)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink.Recorder{}
	g.emit(newEmitter(rec, "gcp"), &ts)
	out := rec.Snapshot()
	if len(out) != 1 || out[0].Value != 12.5 || out[0].Attrs["resource.faas.name"] != "checkout" ||
		out[0].Attrs["resource.cloud.platform"] != "gcp_cloud_run" || out[0].Attrs["resource.faas.version"] != "checkout-00042" ||
		out[0].Attrs["resource.cloud.region"] != "europe-west1" {
		t.Fatalf("%+v", out)
	}
}
