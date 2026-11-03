package custom

import "testing"

func TestEnricherJoinsByAddressHost(t *testing.T) {
	r := EnrichRule{MatchAttr: "net.host.ip", Labels: map[string]string{"__meta_kubernetes_pod_label_team": "team"}}
	e := &Enricher{rules: []EnrichRule{r}, idx: []map[string]map[string]string{r.Index([]TargetSpec{
		{Labels: map[string]string{"__address__": "10.0.0.7:8080", "__meta_kubernetes_pod_label_team": "payments"}},
	})}}
	a := map[string]string{"net.host.ip": "10.0.0.7", "team": ""}
	e.Apply(a)
	if a["team"] != "" {
		t.Fatal("existing attribute overwritten")
	}
	b := map[string]string{"net.host.ip": "10.0.0.7"}
	e.Apply(b)
	if b["team"] != "payments" {
		t.Fatalf("%v", b)
	}
	var nilE *Enricher
	nilE.Apply(b)
}
