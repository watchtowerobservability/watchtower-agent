package cloud

import "testing"

func TestAzureFunctionsPresetExpands(t *testing.T) {
	got := expandPresets(azurePresets, nil, []string{"azure_functions", "unknown"})
	want := azurePresets["azure_functions"]
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestAzureFunctionMetricsMapToFaas(t *testing.T) {
	// The emitted (lower-cased) FunctionExecutionCount and Http5xx become faas.* for the explorer.
	if azureFaasMetric["functionexecutioncount"] != "faas.invocations" {
		t.Fatal("FunctionExecutionCount must map to faas.invocations")
	}
	if azureFaasMetric["http5xx"] != "faas.errors" {
		t.Fatal("Http5xx must map to faas.errors")
	}
}
