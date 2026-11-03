package ascode

import (
	"strings"
	"testing"
)

func TestSpecDiffNamesPanelsAndLeaves(t *testing.T) {
	old := map[string]any{"title": "API", "panels": []any{
		map[string]any{"title": "Latency", "query": "p99"},
		map[string]any{"title": "Errors"},
	}}
	cur := map[string]any{"title": "API v2", "tags": []any{"x"}, "panels": []any{
		map[string]any{"title": "Latency", "query": "p95"},
	}}
	got := strings.Join(SpecDiff(old, cur), "\n")
	for _, want := range []string{
		`panels[0 "Latency"].query: "p99" -> "p95"`,
		`panels[1 "Errors"] removed`,
		`tags: (unset) -> ["x"]`,
		`title: "API" -> "API v2"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if len(SpecDiff(old, old)) != 0 {
		t.Fatal("equal specs must not differ")
	}
	if !strings.Contains(RenderSpecDiff("Dashboard", "api", nil), "no semantic change") {
		t.Fatal("empty diff text")
	}
}
