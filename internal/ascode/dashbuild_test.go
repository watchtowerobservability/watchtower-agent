package ascode

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDashboardBuilderStacksPanelsAndChecksParents(t *testing.T) {
	b, err := NewDashboard().
		Var(Variable{Name: "region", Type: "custom", Options: []string{"eu"}}).
		Var(Variable{Name: "cluster", Type: "custom", Options: []string{"a"}, DependsOn: []string{"region"}}).
		Timeseries("rate", "Rate", "sum(rate(x[5m]))", 12, 6).
		Stat("up", "Up", "up", 12, 6).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version int
		Panels  []struct{ Grid Grid }
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.Panels[1].Grid.Y != 6 {
		t.Fatalf("unexpected spec: %s", b)
	}
	_, err = NewDashboard().Var(Variable{Name: "a", Type: "textbox", DependsOn: []string{"zzz"}}).Build()
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("want unknown parent error, got %v", err)
	}
}
