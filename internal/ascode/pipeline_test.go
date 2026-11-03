package ascode

import (
	"strings"
	"testing"
)

func alert(fields map[string]any) map[string]any {
	st := map[string]any{"type": "alert"}
	for k, v := range fields {
		st[k] = v
	}
	return map[string]any{"stages": []any{st}}
}

func TestCheckAlertStages(t *testing.T) {
	ok := map[string]any{"version": 2, "stages": []any{
		map[string]any{"type": "alert", "name": "payment_errors", "when": `severity == "ERROR"`, "severity": "high", "min_count": 5},
		map[string]any{"type": "drop"},
	}, "groups": []any{map[string]any{"stages": []any{
		map[string]any{"type": "alert", "name": "g", "when": "true", "min_count": float64(1)},
	}}}}
	if err := CheckAlertStages(ok); err != nil {
		t.Fatal(err)
	}
	bad := func(want string, cfg map[string]any) {
		t.Helper()
		err := CheckAlertStages(cfg)
		if err == nil || !strings.HasPrefix(err.Error(), want+":") {
			t.Fatalf("%s: got %v", want, err)
		}
	}
	bad("/stages/0/name", alert(map[string]any{"name": "Bad Name", "when": "true"}))
	bad("/stages/0/when", alert(map[string]any{"name": "a"}))
	bad("/stages/0/severity", alert(map[string]any{"name": "a", "when": "true", "severity": "page"}))
	bad("/stages/0/min_count", alert(map[string]any{"name": "a", "when": "true", "min_count": 0.5}))
	nested := map[string]any{"groups": []any{map[string]any{"children": []any{alert(map[string]any{"when": "true"})}}}}
	bad("/groups/0/children/0/stages/0/name", nested)
}
