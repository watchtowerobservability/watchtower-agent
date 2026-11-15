package container

import "testing"

func TestIntegrationTargets(t *testing.T) {
	cs := []Info{
		{ID: "1", Name: "db", Image: "ghcr.io/x/postgres:16@sha256:ab", State: "running", IP: "10.0.0.2"},
		{ID: "2", Name: "app", Image: "app:1", State: "running", IP: "10.0.0.3", Labels: map[string]string{"watchtower.integration": "redis", "watchtower.port": "6380"}},
		{ID: "3", Name: "web", Image: "nginx", State: "running", IP: "10.0.0.4"},
	}
	if got := IntegrationTargets(cs, false); len(got) != 1 || got[0].Port != 6380 || got[0].Integration != "redis" {
		t.Fatalf("labels only: %+v", got)
	}
	if got := IntegrationTargets(cs, true); len(got) != 3 || got[0].Integration != "postgres" || got[0].Port != 5432 {
		t.Fatalf("by image: %+v", got)
	}
	if MatchedSummary(cs[:2]) != "app(2), db(1)" {
		t.Fatal(MatchedSummary(cs[:2]))
	}
}

func TestNginxStatusURLLabel(t *testing.T) {
	mk := func(u string) []Info {
		return []Info{{ID: "1", Name: "web", Image: "nginx:1", State: "running", IP: "10.0.0.4", Labels: map[string]string{"watchtower.nginx.status_url": u}}}
	}
	got := IntegrationTargets(mk(""), true)
	if len(got) != 1 || got[0].Port != 80 || got[0].Path != "/nginx_status" {
		t.Fatalf("default: %+v", got)
	}
	if got = IntegrationTargets(mk("http://10.0.0.4:8080/st"), true); len(got) != 1 || got[0].Port != 8080 || got[0].Path != "/st" {
		t.Fatalf("override: %+v", got)
	}
	if got = IntegrationTargets(mk("http://169.254.169.254/x"), true); len(got) != 0 {
		t.Fatalf("a foreign host must be refused: %+v", got)
	}
}
