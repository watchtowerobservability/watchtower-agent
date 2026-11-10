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

func TestServiceBusAndAwsStreamPresetsExpand(t *testing.T) {
	got := expandPresets(azurePresets, []string{"ActiveMessages"}, []string{"azure_service_bus"})
	if len(got) != len(azurePresets["azure_service_bus"]) || got[0] != "ActiveMessages" {
		t.Fatalf("service bus preset must add its metrics once: %v", got)
	}
	ns := expandPresets(awsNamespacePresets, []string{"AWS/EC2"}, []string{"data_streams"})
	if len(ns) != 4 || ns[1] != "AWS/Kinesis" || ns[3] != "AWS/SNS" {
		t.Fatalf("data_streams preset: %v", ns)
	}
}

func TestAzureServicePresetsExist(t *testing.T) {
	for _, n := range []string{"azure_vm", "azure_app_service", "azure_sql", "azure_service_bus", "azure_aks"} {
		if len(azurePresets[n]) == 0 {
			t.Errorf("preset %s missing", n)
		}
	}
	if got := expandPresets(azurePresets, nil, []string{"azure_vm", "azure_vm"}); len(got) != len(azurePresets["azure_vm"]) {
		t.Errorf("preset expanded twice: %v", got)
	}
}
