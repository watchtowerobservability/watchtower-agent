package integrations

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchtowerobservability/watchtower-agent/agent/sink"
)

func TestHTTPStatusNginxStubStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nginx_status" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("Active connections: 291 \nserver accepts handled requests\n 16630948 16630948 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n"))
	}))
	defer srv.Close()
	cfg, _ := json.Marshal(map[string]any{"targets": []map[string]string{{"kind": "nginx", "url": srv.URL + "/nginx_status"}}})
	var r sink.Recorder
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_ = HTTPStatus(ctx, cfg, &r)
	wantNames(t, &r, "nginx.connections.active", "nginx.connections.accepted", "nginx.connections.waiting", "wt.integration.up")
	if v, _ := value(&r, "nginx.connections.active"); v != 291 {
		t.Fatalf("active = %v", v)
	}
}
