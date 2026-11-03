package integrations

import (
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestExplainableAndEmitPlan(t *testing.T) {
	for q, want := range map[string]bool{
		"SELECT * FROM t WHERE id = $1": true, "with x as (select 1) select * from x": true,
		"UPDATE t SET a = $1": false, "select 1; drop table t": false, "SELECT * FROM t FOR UPDATE": false,
	} {
		if explainable(q) != want {
			t.Errorf("%q: %v", q, !want)
		}
	}
	r := &sink.Recorder{}
	EmitPlan(r, "postgresql", "42", "SELECT * FROM t WHERE email = 'a@b.c'", `[{"Plan":{"Node Type":"Seq Scan","Total Cost":12.5}}]`, time.Now())
	a := r.Samples[0].Attrs
	if a["db.plan.total_cost"] != "12.5" || a["db.plan.node_type"] != "Seq Scan" || a["db.query.text"] == "SELECT * FROM t WHERE email = 'a@b.c'" {
		t.Fatalf("%v", a)
	}
}
