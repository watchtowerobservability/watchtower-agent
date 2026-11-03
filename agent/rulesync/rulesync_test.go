package rulesync

import (
	"context"
	"net/http"
	"testing"
)

const crds = `{"items":[{"metadata":{"name":"api","namespace":"prod"},"spec":{"groups":[
 {"name":"latency","rules":[{"alert":"Slow","expr":"x > 1"}]},
 {"name":"","rules":[]}]}}]}`

func TestSyncAppliesChangedAndDeletesVanished(t *testing.T) {
	list := crds
	var calls []string
	s := &syncer{
		list: func(context.Context) ([]byte, error) { return []byte(list), nil },
		do: func(_ context.Context, m, rel string, body any) error {
			calls = append(calls, m+" "+rel)
			if m == http.MethodPut && body.(map[string]any)["name"] != "k8s.prod.api.latency" {
				t.Fatalf("body name %v", body)
			}
			return nil
		},
		synced: map[string][32]byte{},
	}
	ctx := context.Background()
	for range 2 {
		if err := s.once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(calls) != 1 || calls[0] != "PUT rule-groups/k8s.prod.api.latency" {
		t.Fatalf("unchanged group re-applied or wrong call: %v", calls)
	}
	list = `{"items":[]}`
	if err := s.once(ctx); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1] != "DELETE rule-groups/k8s.prod.api.latency" || len(s.synced) != 0 {
		t.Fatalf("vanished group not deleted: %v", calls)
	}
}
