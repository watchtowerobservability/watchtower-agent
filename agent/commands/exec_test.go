package commands

import (
	"context"
	"testing"
)

func TestExecRefusesUnlistedAndExtraFields(t *testing.T) {
	r := Exec(context.Background(), nil, []byte(`{"id":"c1","request":{"name":"nope","args":{}}}`))
	if r.ID != "c1" || r.OK || r.Error == "" {
		t.Fatalf("unlisted command not refused: %+v", r)
	}
	r = Exec(context.Background(), nil, []byte(`{"id":"c2","request":{"name":"x","script":"rm -rf /"}}`))
	if r.OK || r.Error == "" {
		t.Fatalf("extra field accepted: %+v", r)
	}
}
