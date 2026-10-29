package v1

import "testing"

func TestInjectPatchSkipsOptOutAndExisting(t *testing.T) {
	if InjectPatch(map[string]string{InjectAnnotation: "false"}, [][]string{{}}, "10.0.0.1", 4318) != nil {
		t.Fatal("opted-out pod patched")
	}
	ops := InjectPatch(nil, [][]string{{}, {"A"}, {"OTEL_EXPORTER_OTLP_ENDPOINT"}}, "10.0.0.1", 4318)
	if len(ops) != 2 || ops[0].Path != "/spec/containers/0/env" || ops[1].Path != "/spec/containers/1/env/-" {
		t.Fatalf("patch %+v", ops)
	}
}
