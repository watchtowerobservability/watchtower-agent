package custom

import "testing"

func TestPprofURL(t *testing.T) {
	u, err := pprofURL(TargetSpec{Labels: map[string]string{"__address__": "10.0.0.5:6060"}}, "cpu", 10)
	if err != nil || u != "http://10.0.0.5:6060/debug/pprof/profile?seconds=10" {
		t.Fatalf("%q %v", u, err)
	}
	u, _ = pprofURL(TargetSpec{URL: "https://api:8443/base/"}, "heap", 10)
	if u != "https://api:8443/base/debug/pprof/heap" {
		t.Fatal(u)
	}
	if _, err := pprofURL(TargetSpec{URL: "file:///etc/passwd"}, "heap", 10); err == nil {
		t.Fatal("non-http target accepted")
	}
}
