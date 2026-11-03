package ascode

import "testing"

func TestLokiRuleGroupNames(t *testing.T) {
	ns, g, err := splitLokiName("app/errors")
	if err != nil || ns != "app" || g != "errors" {
		t.Fatalf("got %q %q %v", ns, g, err)
	}
	for _, bad := range []string{"errors", "/errors", "app/"} {
		if _, _, err := splitLokiName(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if k := ByKind("LokiRuleGroup"); k == nil || k.ops == nil {
		t.Fatal("LokiRuleGroup is not registered with its ops")
	}
}
