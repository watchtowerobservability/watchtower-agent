package container

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

// fakeEngine ignores filters and lists one container of ours and one foreign one, recording
// every request, so the test proves both the server-side filter and the client-side guard.
func fakeEngine(t *testing.T) (string, func() []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("unix socket test")
	}
	dir, err := os.MkdirTemp("", "wtd") // t.TempDir() paths can pass macOS's 104-byte socket limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var reqs []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.URL.RequestURI())
		mu.Unlock()
		switch {
		case r.URL.Path == "/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"ours","Names":["/a"],"Labels":{"p":"me","x":"1"}},{"Id":"foreign","Names":["/b"],"Labels":{"p":"other"}}]`))
		case strings.HasSuffix(r.URL.Path, "/stats"):
			_, _ = w.Write([]byte(`{"memory_stats":{"usage":1}}`))
		}
	}))
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return "unix://" + sock, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), reqs...) }
}

func TestListAndEventsSendLabelFilterAndSkipForeign(t *testing.T) {
	ep, reqs := fakeEngine(t)
	d, err := NewDocker(ep)
	if err != nil {
		t.Fatal(err)
	}
	d.Labels = map[string]string{"p": "me"}
	var r sink.Recorder
	list, err := (&Poller{}).Collect(context.Background(), d, &r)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "ours" {
		t.Fatalf("list: %+v", list)
	}
	_ = d.Events(context.Background(), time.Unix(0, 0), &r)
	var sawList, sawEvents bool
	for _, u := range reqs() {
		if strings.Contains(u, "foreign") {
			t.Fatalf("foreign container touched: %s", u)
		}
		q, _ := http.NewRequest(http.MethodGet, "http://x"+u, nil)
		var f map[string][]string
		if raw := q.URL.Query().Get("filters"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &f)
		}
		ok := len(f["label"]) == 1 && f["label"][0] == "p=me"
		switch q.URL.Path {
		case "/containers/json":
			sawList = ok
		case "/events":
			sawEvents = ok && f["type"][0] == "container"
		}
	}
	if !sawList || !sawEvents {
		t.Fatalf("label filter missing: %v", reqs())
	}
}

func TestRunRequireLabelsWithoutLabelsTouchesNothing(t *testing.T) {
	ep, reqs := fakeEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	raw, _ := json.Marshal(Config{DockerHost: ep, RequireLabels: true})
	if err := Run(ctx, raw, &sink.Recorder{}); err != nil {
		t.Fatal(err)
	}
	if n := len(reqs()); n != 0 {
		t.Fatalf("engine called %d times", n)
	}
}
