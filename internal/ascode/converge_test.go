package ascode_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/watchtowerobservability/watchtower-agent/internal/ascode"
)

func TestRoutingApplySendsTheLiveVersion(t *testing.T) {
	c, _ := client(t)
	docs, err := ascode.ParseDocs([]byte("apiVersion: watchtower.dev/v1\nkind: Routing\nmetadata: {name: r}\nspec: {id: root, receiver: slack}\n"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.Plan(context.Background(), docs, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(context.Background(), plan, false, io.Discard); err != nil {
		t.Fatalf("apply must carry If-Match (the fake answers 428 otherwise): %v", err)
	}
}

func TestArraysCompareAsSubsets(t *testing.T) {
	k := ascode.ByKind("Schedule")
	live := map[string]any{"layers": []any{
		map[string]any{"id": "lyr_1", "rotation_s": 86400.0, "handoff": "09:00", "users": []any{"usr_a", "usr_b"}},
	}}
	min := map[string]any{"layers": []any{map[string]any{"rotation_s": 86400.0, "users": []any{"usr_a", "usr_b"}}}}
	if d := ascode.Drift(k, min, live); len(d) != 0 {
		t.Fatalf("server ids and defaults must not differ: %v", d)
	}
	min["layers"].([]any)[0].(map[string]any)["users"] = []any{"usr_a"}
	if d := ascode.Drift(k, min, live); len(d) != 1 || !strings.HasPrefix(d[0], "layers[0].users") {
		t.Fatalf("a real change must show with its element path: %v", d)
	}
}

func TestDiffDoesNotEscapeAngleBrackets(t *testing.T) {
	d := ascode.Drift(ascode.ByKind("Template"), map[string]any{"body": "<b>x</b>"}, map[string]any{"body": "y"})
	if len(d) != 1 || !strings.Contains(d[0], "<b>") {
		t.Fatalf("drift = %v", d)
	}
}
