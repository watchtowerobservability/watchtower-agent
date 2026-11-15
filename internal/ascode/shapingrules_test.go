package ascode

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShapingRuleNames(t *testing.T) {
	if got := shapingName("logs", "drop", ""); got != "logs/drop" {
		t.Fatalf("got %q", got)
	}
	a, b := shapingName("logs", "drop", `level = "debug"`), shapingName("logs", "drop", `level = "trace"`)
	if a == b || !strings.HasPrefix(a, "logs/drop/") || len(a) != len("logs/drop/")+8 {
		t.Fatalf("names %q %q", a, b)
	}
	if err := checkShapingName("noisy", map[string]any{"signal": "logs", "kind": "drop"}); err == nil || !strings.Contains(err.Error(), `"logs/drop"`) {
		t.Fatalf("a wrong name must say the right one: %v", err)
	}
	if err := checkShapingName("logs/drop", map[string]any{"signal": "logs", "kind": "drop"}); err != nil {
		t.Fatal(err)
	}
	if k := ByKind("ShapingRule"); k == nil || k.ops == nil {
		t.Fatal("ShapingRule is not registered with its ops")
	}
}

func TestShapingRuleListSkipsGeneratedRulesAndKeysByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{
			map[string]any{"id": "r1", "signal": "logs", "kind": "drop", "match": nil, "source": "manual"},
			map[string]any{"id": "r2", "signal": "logs", "kind": "sample", "match": nil, "source": "suggestion"},
		}, "next_cursor": nil})
	}))
	defer srv.Close()
	c, err := New(srv.URL, "k", "prj_1", nil)
	if err != nil {
		t.Fatal(err)
	}
	items, err := shapingRuleOps{}.list(context.Background(), c)
	if err != nil || len(items) != 1 || items["logs/drop"].Ref != "r1" {
		t.Fatalf("items %v err %v", items, err)
	}
}
