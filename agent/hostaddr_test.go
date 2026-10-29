package main

import "testing"

func TestJSONListSortsDedupesAndCaps(t *testing.T) {
	if got := jsonList([]string{"10.0.0.2", "10.0.0.1", "10.0.0.2"}); got != `["10.0.0.1","10.0.0.2"]` {
		t.Fatalf("got %s", got)
	}
	if jsonList(nil) != "" {
		t.Fatal("no addresses, no attribute")
	}
	var many []string
	for i := range 40 {
		many = append(many, string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if n := len(jsonList(many)); n > 16*6 {
		t.Fatalf("not capped: %d", n)
	}
}

func TestHostAddrsNeverReportLoopback(t *testing.T) {
	ips, _ := hostAddrs()
	for _, bad := range []string{"127.0.0.1", "::1"} {
		if ips != "" && contains(ips, `"`+bad+`"`) {
			t.Fatalf("loopback in %s", ips)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
