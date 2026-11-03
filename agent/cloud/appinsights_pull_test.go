package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

const aiQueryResult = `{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated"},{"name":"Type"},{"name":"Id"},
 {"name":"OperationId"},{"name":"ParentId"},{"name":"Name"},{"name":"Success"},{"name":"ResultCode"},{"name":"DurationMs"},
 {"name":"AppRoleName"},{"name":"Properties"},{"name":"_wt_ingested"}],
 "rows":[["2026-10-28T10:00:00.1234567Z","AppRequests","b7ad6b7169203331","0af7651916cd43dd8448eb211c80319c",
  "0af7651916cd43dd8448eb211c80319c","GET /pay",false,"500",250,"checkout","{\"tier\":\"gold\",\"n\":3}","2026-10-28T10:00:30Z"]]}]}`

// The hosted pull reads rows by ingestion time, maps them like the Event Hubs path, and does not
// ship a row twice when the next run's overlap returns it again.
func TestAppInsightsPullReadsNewRowsOnce(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_ = r.ParseForm()
			if r.Form.Get("scope") != "https://api.loganalytics.io/.default" || r.Form.Get("client_secret") != "s" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		if r.URL.Path != "/v1/workspaces/ws1/query" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var q struct {
			Query    string `json:"query"`
			Timespan string `json:"timespan"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		queries = append(queries, q.Query+" "+q.Timespan)
		_, _ = w.Write([]byte(aiQueryResult))
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]any{"tenant_id": "t", "client_id": "c", "client_secret": "s",
		"workspaces": []string{"ws1"}, "login_endpoint": srv.URL, "endpoint": srv.URL})
	p, err := newAppInsights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.cl = srv.Client()
	var spans []*tracepb.Span
	var res []map[string]string
	ship := func(r map[string]string, s []*tracepb.Span) { res = append(res, r); spans = append(spans, s...) }
	now := time.Date(2026, 10, 28, 10, 1, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if err := p.pullWorkspace(context.Background(), "ws1", now, ship); err != nil {
			t.Fatal(err)
		}
	}
	if len(spans) != 1 || len(queries) != 2 {
		t.Fatalf("%d spans, %d queries", len(spans), len(queries))
	}
	sp := spans[0]
	if sp.Kind != tracepb.Span_SPAN_KIND_SERVER || sp.Status.Code != tracepb.Status_STATUS_CODE_ERROR || sp.Name != "GET /pay" ||
		res[0]["service.name"] != "checkout" || aiAttr(sp, "tier") != "gold" || aiAttr(sp, "n") != "3" {
		t.Fatalf("%v %v", sp, res[0])
	}
	// first run: from one minute before now, less the overlap; then from the newest ingestion time read
	if !strings.Contains(queries[0], "datetime(2026-10-28T09:59:00Z)") || !strings.Contains(queries[1], "datetime(2026-10-28T09:59:30Z)") ||
		!strings.HasSuffix(queries[0], " P1D") || !strings.Contains(queries[0], "ingestion_time()") {
		t.Fatal(queries)
	}
	for _, bad := range []string{`{"tenant_id":"t","client_id":"c","client_secret":"s","workspaces":["../x"]}`,
		`{"tenant_id":"t","client_id":"c","client_secret":"s","workspaces":[]}`} {
		if _, err := newAppInsights(json.RawMessage(bad)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

type memCursors struct {
	at      map[string]time.Time
	flushed int
}

func (m *memCursors) LoadCursor(_ context.Context, pull, key string) (time.Time, bool) {
	at, ok := m.at[pull+"/"+key]
	return at, ok
}

func (m *memCursors) SaveCursor(_ context.Context, pull, key string, at time.Time) error {
	m.at[pull+"/"+key] = at
	return nil
}

func (m *memCursors) Flush(context.Context) error { m.flushed++; return nil }

// A restarted process resumes from the position saved after the last flush, not from now.
func TestAppInsightsPullResumesFromTheSavedPosition(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		var q struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		queries = append(queries, q.Query)
		_, _ = w.Write([]byte(aiQueryResult))
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]any{"tenant_id": "t", "client_id": "c", "client_secret": "s", "pull_id": "p1",
		"workspaces": []string{"ws1"}, "login_endpoint": srv.URL, "endpoint": srv.URL})
	store := &memCursors{at: map[string]time.Time{}}
	now := time.Date(2026, 10, 28, 10, 1, 0, 0, time.UTC)
	for i := 0; i < 2; i++ { // the second pull is a fresh process, an hour later
		p, err := newAppInsights(cfg)
		if err != nil {
			t.Fatal(err)
		}
		p.cl, p.store = srv.Client(), store
		if err := p.pullWorkspace(context.Background(), "ws1", now.Add(time.Duration(i)*time.Hour), func(map[string]string, []*tracepb.Span) {}); err != nil {
			t.Fatal(err)
		}
	}
	if store.flushed != 2 || !store.at["p1/ws1"].Equal(time.Date(2026, 10, 28, 10, 0, 30, 0, time.UTC)) {
		t.Fatal(store.flushed, store.at)
	}
	// the first run starts at now; the restarted one at the saved ingestion time, less the overlap
	if !strings.Contains(queries[0], "datetime(2026-10-28T09:59:00Z)") || !strings.Contains(queries[1], "datetime(2026-10-28T09:59:30Z)") {
		t.Fatal(queries)
	}
}

type flushCounter struct {
	sink.Recorder
	n int
}

func (f *flushCounter) Flush(context.Context) error { f.n++; return nil }
func (f *flushCounter) Buffered() int               { return 0 }

// A BYOC agent keeps the position in its state dir: a fresh store over the same file resumes,
// and the save waits for the sink's flush.
func TestFileCursorsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	out := &flushCounter{}
	at := time.Date(2026, 10, 28, 10, 0, 30, 0, time.UTC)
	f := newFileCursors(dir, out)
	if _, ok := f.LoadCursor(context.Background(), localPullID, "ws1"); ok {
		t.Fatal("empty dir has a position")
	}
	if err := f.Flush(context.Background()); err != nil || out.n != 1 {
		t.Fatal(err, out.n)
	}
	if err := f.SaveCursor(context.Background(), localPullID, "ws1", at); err != nil {
		t.Fatal(err)
	}
	got, ok := newFileCursors(dir, out).LoadCursor(context.Background(), localPullID, "ws1")
	if !ok || !got.Equal(at) {
		t.Fatal(got, ok)
	}
}
