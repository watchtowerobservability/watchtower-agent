package logs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestDockerFollowerFiltersByLabelServerSide(t *testing.T) {
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.URL.RequestURI())
		mu.Unlock()
		if r.URL.Path == "/containers/json" { // ignores the filter: the client must still skip "foreign"
			_, _ = w.Write([]byte(`[{"Id":"ours","Labels":{"p":"me"}},{"Id":"foreign","Labels":{"p":"other"}}]`))
		}
	}))
	defer srv.Close()
	f := newDockerFollower(DockerLogs{Host: srv.URL, Labels: map[string]string{"p": "me"}}, "", &sink.Recorder{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := f.scan(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	q, _ := http.NewRequest(http.MethodGet, srv.URL+reqs[0], nil)
	var filt map[string][]string
	_ = json.Unmarshal([]byte(q.URL.Query().Get("filters")), &filt)
	if q.URL.Path != "/containers/json" || len(filt["label"]) != 1 || filt["label"][0] != "p=me" {
		t.Fatalf("no server-side label filter: %v", reqs)
	}
	var followed bool
	for _, u := range reqs {
		if strings.Contains(u, "foreign") {
			t.Fatalf("foreign container followed: %s", u)
		}
		followed = followed || strings.HasPrefix(u, "/containers/ours/")
	}
	if !followed {
		t.Fatalf("own container not followed: %v", reqs)
	}
}

func TestDockerRequireLabelsWithoutLabelsFollowsNothing(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := RunDocker(ctx, DockerLogs{Host: srv.URL, RequireLabels: true}, "", &sink.Recorder{}); err != nil || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}
