package rulesync

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestMergeAlertmanagerPrefixesAndScopesByNamespace(t *testing.T) {
	raw := `{"items":[{"metadata":{"name":"team","namespace":"prod"},"spec":{
	  "route":{"receiver":"slack","groupBy":["alertname"],"groupWait":"30s","matchers":[{"name":"severity","value":"critical","matchType":"="}]},
	  "receivers":[{"name":"slack","slackConfigs":[{"channel":"#ops","apiURL":{"name":"s","key":"url"},"sendResolved":true}]}],
	  "inhibitRules":[{"sourceMatch":[{"name":"severity","value":"critical"}],"targetMatch":[{"name":"severity","value":"warning"}],"equal":["alertname"]}]}}]}`
	out, err := MergeAlertmanager([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"receiver":"prod/team/slack"`, `"group_by":["alertname"]`, `"group_wait":"30s"`,
		`"namespace=\"prod\""`, `"severity=\"critical\""`, `"send_resolved":true`, `"name":"prod/team/slack"`, `"source_matchers"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, "api_url") {
		t.Errorf("secret reference kept: %s", s)
	}
}

func TestSyncPostsAlertmanagerOnlyOnChange(t *testing.T) {
	var posts int
	s := &syncer{
		list:   func(context.Context) ([]byte, error) { return []byte(`{"items":[]}`), nil },
		listAM: func(context.Context) ([]byte, error) { return []byte(`{"items":[]}`), nil },
		do: func(_ context.Context, m, rel string, _ any) error {
			if m == http.MethodPost && strings.HasPrefix(rel, "routing:import-alertmanager?apply=true") {
				posts++
			}
			return nil
		},
		synced: map[string][32]byte{},
	}
	for range 3 {
		if err := s.once(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if posts != 1 {
		t.Fatalf("posts = %d, want 1", posts)
	}
}
