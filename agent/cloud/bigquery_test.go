package cloud

import "testing"

func TestBigQueryPresetExpandsToNamedSeries(t *testing.T) {
	got := expandPresets(gcpPresets, nil, []string{"bigquery"})
	if len(got) != 5 {
		t.Fatalf("preset: %v", got)
	}
	if n := gcpName(got[0]); n != "cloud.gcp.bigquery.job.num_in_flight" {
		t.Fatalf("name: %s", n)
	}
}
