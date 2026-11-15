package ascode

import "testing"

func TestExportDropsServerOnlyFields(t *testing.T) {
	d := ExportDoc(ByKind("Monitor"), "api", map[string]any{"name": "api", "kind": "http", "last_run_at": "x", "rule_id": "r", "id": "m"})
	if _, ok := d.Spec["last_run_at"]; ok {
		t.Fatal("last_run_at exported")
	}
	if _, ok := d.Spec["rule_id"]; ok || d.Spec["kind"] != "http" {
		t.Fatalf("spec: %v", d.Spec)
	}
	r := ExportDoc(ByKind("Receiver"), "slack", map[string]any{"name": "slack", "last_delivery": map[string]any{"ok": true}})
	if _, ok := r.Spec["last_delivery"]; ok {
		t.Fatal("last_delivery exported")
	}
}

func TestRoutePlanLinesNameTheReceiver(t *testing.T) {
	spec := map[string]any{"routes": []any{map[string]any{"receiver": "a"}, map[string]any{"receiver": "b", "routes": []any{map[string]any{"receiver": "c"}}}}}
	got := withRouteReceivers([]string{"routes[1].routes[0].match: x -> y", "receiver: a -> b"}, spec)
	if got[0] != "routes[1].routes[0].match: x -> y  [receiver c]" || got[1] != "receiver: a -> b" {
		t.Fatalf("%q", got)
	}
}
