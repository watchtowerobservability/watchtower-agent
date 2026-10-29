package custom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A scraped label (or a configured one) that tries to name the OTLP resource is dropped, so a
// pod's metrics page can never forge a host or workload identity.
func TestScrapedResourceLabelIsDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, "# TYPE app_up gauge\napp_up{\"resource.host.name\"=\"db-prod-1\",\"resource.k8s.deployment.uid\"=\"victim\",ok=\"1\"} 1\n")
	}))
	defer srv.Close()
	rc := &rec{}
	if err := (Prometheus{}).Scrape(context.Background(), TargetSpec{URL: srv.URL}, rc, time.Now()); err != nil {
		t.Fatal(err)
	}
	s, ok := rc.find("gauge", "app_up", map[string]string{"ok": "1"})
	if !ok {
		t.Fatalf("sample missing: %+v", rc.s)
	}
	for k := range s.attrs {
		if strings.HasPrefix(k, "resource.") {
			t.Fatalf("resource-prefixed label survived: %s", k)
		}
	}
}
